mutable struct SSLConfig
    data::Ptr{Cvoid}
    rng
    chain::CRT
    dbg
    cert
    key
    alpn_protos

    function SSLConfig()
        conf = new()
        conf.data = Libc.malloc(1000)  # 360
        ccall((:mbedtls_ssl_config_init, libmbedtls), Cvoid, (Ptr{Cvoid},), conf.data)
        @compat finalizer(conf->begin
            ccall((:mbedtls_ssl_config_free, libmbedtls), Cvoid, (Ptr{Cvoid},), conf.data)
            Libc.free(conf.data)
        end, conf)
        conf
    end
end

Base.show(io::IO, c::SSLConfig) = print(io, "MbedTLS.SSLConfig()")

mutable struct SSLContext <: IO
    data::Ptr{Cvoid}
    datalock::ReentrantLock
    decrypted_data_ready::Condition
    config::SSLConfig
    isopen::Bool
    close_notify_sent::Bool
    bio

    function SSLContext()
        ctx = new()
        ctx.data = Libc.malloc(1000)  # 488
        ctx.datalock = ReentrantLock()
        ctx.decrypted_data_ready = Condition()
        ctx.isopen = false
        ctx.close_notify_sent = false
        ccall((:mbedtls_ssl_init, libmbedtls), Cvoid, (Ptr{Cvoid},), ctx.data)
        @compat finalizer(ctx->begin
            ccall((:mbedtls_ssl_free, libmbedtls), Cvoid, (Ptr{Cvoid},), ctx.data)
            Libc.free(ctx.data)
        end, ctx)
        ctx
    end
end

macro lockdata(ctx, expr)
    esc(quote
        if islocked($ctx.datalock)
            println("tls lock wait...")
        end
        lock($ctx.datalock)
        @assert $ctx.datalock.reentrancy_cnt == 1
        try
            $expr
        finally
            unlock($ctx.datalock)
        end
    end)
end

function config_defaults!(config::SSLConfig; endpoint=MBEDTLS_SSL_IS_CLIENT,
    transport=MBEDTLS_SSL_TRANSPORT_STREAM, preset=MBEDTLS_SSL_PRESET_DEFAULT)
    @err_check ccall((:mbedtls_ssl_config_defaults, libmbedtls), Cint,
        (Ptr{Cvoid}, Cint, Cint, Cint),
        config.data, endpoint, transport, preset)
end

function authmode!(config::SSLConfig, auth)
    ccall((:mbedtls_ssl_conf_authmode, libmbedtls), Cvoid,
        (Ptr{Cvoid}, Cint),
        config.data, auth)
end

function rng!(config::SSLConfig, f_rng::Ptr{Cvoid}, rng)
    ccall((:mbedtls_ssl_conf_rng, libmbedtls), Cvoid,
        (Ptr{Cvoid}, Ptr{Cvoid}, Any),
        config.data, f_rng, rng)
end

function rng!(config::SSLConfig, rng::AbstractRNG)
    config.rng = rng
    rng!(config, c_rng[], rng)
end

function ca_chain!(config::SSLConfig, chain=crt_parse_file(joinpath(dirname(@__FILE__), "../deps/cacert.pem")))
    config.chain = chain
    ccall((:mbedtls_ssl_conf_ca_chain, libmbedtls), Cvoid,
        (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}),
        config.data, chain.data, C_NULL)
end

function own_cert!(config::SSLConfig, cert::CRT, key::PKContext)
    config.cert = cert
    config.key = key
    @err_check ccall((:mbedtls_ssl_conf_own_cert, libmbedtls), Cint,
        (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}),
        config.data, cert.data, key.data)
end

function setup!(ctx::SSLContext, conf::SSLConfig)
    @lockdata ctx begin
        ctx.config = conf
        @err_check ccall((:mbedtls_ssl_setup, libmbedtls), Cint,
            (Ptr{Cvoid}, Ptr{Cvoid}),
            ctx.data, conf.data)
    end
end

function set_bio!(ssl_ctx::SSLContext, ctx, f_send::Ptr{Cvoid}, f_recv::Ptr{Cvoid})
    @lockdata ssl_ctx begin
        ccall((:mbedtls_ssl_set_bio, libmbedtls), Cvoid,
            (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}),
            ssl_ctx.data, ctx, f_send, f_recv, C_NULL)
    end
end

function f_send(c_ctx, c_msg, sz)
    jl_ctx = unsafe_pointer_to_objref(c_ctx)
    return Cint(unsafe_write(jl_ctx, c_msg, sz))
end

function f_recv(c_ctx, c_msg, sz)
    @assert sz > 0
    jl_ctx = unsafe_pointer_to_objref(c_ctx)
    n = bytesavailable(jl_ctx)
    if n == 0
        return Cint(MBEDTLS_ERR_SSL_WANT_READ)
    end
    n = min(sz, n)
    unsafe_read(jl_ctx, c_msg, n)
    return Cint(n)
end

function set_bio!(ssl_ctx::SSLContext, jl_ctx::T) where {T<:IO}
    ssl_ctx.bio = jl_ctx
    set_bio!(ssl_ctx, pointer_from_objref(ssl_ctx.bio), c_send[], c_recv[])
    nothing
end

function dbg!(conf::SSLConfig, f::Ptr{Cvoid}, p)
    ccall((:mbedtls_ssl_conf_dbg, libmbedtls), Cvoid,
        (Ptr{Cvoid}, Ptr{Cvoid}, Any),
        conf.data, f, p)
end

function f_dbg(f, level, filename, number, msg)
    f(level, unsafe_string(filename), number, unsafe_string(msg))
    nothing
end

function dbg!(conf::SSLConfig, f)
    conf.dbg = f
    dbg!(conf, c_dbg[], f)
    nothing
end

@enum(DebugThreshold,
    NONE = 0,
    ERROR,
    STATE_CHANGE,
    INFO,
    VERBOSE)

function set_dbg_level(level)
    ccall((:mbedtls_debug_set_threshold, libmbedtls), Cvoid,
        (Cint,), Cint(level))
    nothing
end


Base.wait(ctx::SSLContext) = wait(ctx.decrypted_data_ready)

notify_error(ctx::SSLContext, e) = notify(ctx.decrypted_data_ready, e;
                                          all=true, error=true)


"""
    pump(::SSLContext)

For as long as the SSLContext is open:
 - Notify readers when decrypted data is available.
 - Check the TLS buffers for encrypted data that needs to be processed.
   (zero-byte ssl_read(), see https://esp32.com/viewtopic.php?t=1101#p4884)
 - If the peer sends a close_notify message or closes then TCP connection,
   then send EOFError to readers and close the SSLContext.
 - Wait for more encrypted data to arrive.

State management:
 - `ctx.isopen` is set `false` only when `unsafe_read` or `pump` throws an error.
 - `close(::TCPSocket)` is called only at the end of the `pump` loop.
 - `close(::SSLContext)` just calls `ssl_close_notify`.
"""
function pump(ctx::SSLContext)

    @assert ctx.isopen

    try
        while ctx.isopen

            @show ssl_get_bytes_avail(ctx)
            if ssl_get_bytes_avail(ctx) > 0
                notify(ctx.decrypted_data_ready)
            end

            @show ssl_check_pending(ctx)
            if ssl_check_pending(ctx) || !eof(ctx.bio)
                n = ssl_read(ctx, C_NULL, 0)
                @show n
                @show n == MBEDTLS_ERR_SSL_WANT_READ
                if n == MBEDTLS_ERR_SSL_WANT_READ || n >= 0
                    continue
                    #FIXME do we spin fast if the TLS buffer fills up?
                elseif !ctx.close_notify_sent
                    if n == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY
                        notify_error(ctx, EOFError())
                    else
                        notify_error(ctx, MbedException(n))
                    end
                end
                break
            end

            @show isopen(ctx.bio)
            if !isopen(ctx.bio)
                if !ctx.close_notify_sent
                    notify_error(ctx, EOFError())
                end
                break
            end
        end
    catch e
        ctx.isopen = false
        notify_error(ctx, e)
    finally
        close(ctx.bio)
    end
end

function handshake(ctx::SSLContext)

    ctx.isopen && throw(ArgumentError("handshake() already done!"))

    while true
        n = @lockdata ctx begin
            ccall((:mbedtls_ssl_handshake, libmbedtls), Cint,
                  (Ptr{Cvoid},), ctx.data)
        end
        if n == 0
            break
        end
        if n == MBEDTLS_ERR_SSL_WANT_READ
            eof(ctx.bio)
        else
            mbed_err(n)
        end
    end

    ctx.isopen = true

    @static if VERSION < v"0.7.0-alpha.0"
        @schedule pump(ctx)
    else
        @async    pump(ctx)
    end

    return
end

function set_alpn!(conf::SSLConfig, protos)
    conf.alpn_protos = protos
    @err_check ccall((:mbedtls_ssl_conf_alpn_protocols, libmbedtls), Cint,
                     (Ptr{Cvoid}, Ptr{Ptr{Cchar}}), conf.data, protos)
    nothing
end

function alpn_proto(ctx::SSLContext)
    rv = ccall((:mbedtls_ssl_get_alpn_protocol, libmbedtls), Ptr{Cchar},
               (Ptr{Cvoid},), ctx.data)
    unsafe_string(rv)
end

import Base: unsafe_read, unsafe_write

function Base.unsafe_write(ctx::SSLContext, msg::Ptr{UInt8}, N::UInt)
    nw = 0
    while nw < N
        ret = @lockdata ctx begin
            ccall((:mbedtls_ssl_write, libmbedtls), Cint,
                  (Ptr{Cvoid}, Ptr{Cvoid}, Csize_t),
                  ctx.data, msg, N - nw)
        end
        ret < 0 && mbed_err(ret)
        nw += ret
        msg += ret
    end
    return Int(nw)
end

Base.write(ctx::SSLContext, msg::UInt8) = write(ctx, Ref(msg))

function Base.unsafe_read(ctx::SSLContext, buf::Ptr{UInt8}, nbytes::UInt; err=true)
    nread::UInt = 0
    while nread < nbytes

        n = try
            ssl_read(ctx, buf + nread, nbytes - nread)
        catch e
            ctx.isopen = false
            rethrow(e)
        end

        if n == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY || n == 0
            println("**sslclose in unsafe_read")
            ctx.isopen = false
            err ? throw(EOFError()) : return nread
        elseif n == MBEDTLS_ERR_SSL_WANT_READ
            wait(ctx.decrypted_data_ready)
        elseif n < 0
            ctx.isopen = false
            println("**mbed_err in unsafe_read $n")
            mbed_err(n)
        elseif n == 0
            println("**zero return in unafe_read")
        else
            nread += n
        end
    end
end

Base.readbytes!(ctx::SSLContext, buf::Vector{UInt8}, nbytes=length(buf)) = readbytes!(ctx, buf, UInt(nbytes))
function Base.readbytes!(ctx::SSLContext, buf::Vector{UInt8}, nbytes::UInt)
    nr = unsafe_read(ctx, pointer(buf), nbytes; err=false)
    if nr !== nothing
        resize!(buf, nr::UInt)
    else
        nr = nbytes
    end
    return Int(nr::UInt)
end

Base.readavailable(ctx::SSLContext) = read(ctx, bytesavailable(ctx))

function Base.eof(ctx::SSLContext)
    while ssl_get_bytes_avail(ctx) == 0
        if !ctx.isopen
            return true
        end
        wait(ctx.decrypted_data_ready)
    end
    return false
end

function Base.close(ctx::SSLContext)
    if ctx.isopen
        ssl_close_notify(ctx)
    end
    nothing
end

Base.isopen(ctx::SSLContext) = ctx.isopen

function get_peer_cert(ctx::SSLContext)
    data = ccall((:mbedtls_ssl_get_peer_cert, libmbedtls), Ptr{Cvoid}, (Ptr{Cvoid},), ctx.data)
    return CRT(data)
end

function get_version(ctx::SSLContext)
    if isdefined(ctx, :config)
        data = ccall((:mbedtls_ssl_get_version, libmbedtls), Ptr{UInt8}, (Ptr{Cvoid},), ctx.data)
        return unsafe_string(data)
    else
        throw(ArgumentError("`ctx` hasn't been initialized with an MbedTLS.SSLConfig; run `MbedTLS.setup!(ctx, conf)`"))
    end
end

function get_ciphersuite(ctx::SSLContext)
    data = ccall((:mbedtls_ssl_get_ciphersuite, libmbedtls), Ptr{UInt8}, (Ptr{Cvoid},), ctx.data)
    return unsafe_string(data)
end

@static if isdefined(Base, :bytesavailable)
    Base.bytesavailable(ctx::SSLContext) = ssl_get_bytes_avail(ctx)
else
    Base.nb_available(ctx::SSLContext) = ssl_get_bytes_avail(ctx)
end

function ssl_get_bytes_avail(ctx::SSLContext)::Int
    @lockdata ctx begin
        return ccall((:mbedtls_ssl_get_bytes_avail, libmbedtls),
                     Csize_t, (Ptr{Cvoid},), ctx.data)
    end
end

function ssl_check_pending(ctx::SSLContext)::Bool
    @lockdata ctx begin
        return ccall((:mbedtls_ssl_check_pending, libmbedtls),
                     Cint, (Ptr{Cvoid},), ctx.data) > 0
    end
end

function ssl_read(ctx::SSLContext, ptr, n)::Int
    @lockdata ctx begin
        return ccall((:mbedtls_ssl_read, libmbedtls), Cint,
                     (Ptr{Cvoid}, Ptr{Cvoid}, Csize_t),
                     ctx.data, ptr, n)
    end
end

function ssl_close_notify(ctx::SSLContext)
    if !ctx.close_notify_sent
        ctx.close_notify_sent = true
        @lockdata ctx begin
            return ccall((:mbedtls_ssl_close_notify, libmbedtls),
                         Cint, (Ptr{Cvoid},), ctx.data)
        end
    end
end

function hostname!(ctx::SSLContext, hostname)
    @err_check ccall((:mbedtls_ssl_set_hostname, libmbedtls), Cint,
      (Ptr{Cvoid}, Cstring), ctx.data, hostname)
end

#Compat.Sockets.getsockname(ctx::SSLContext) = Compat.Sockets.getsockname(ctx.bio)

const c_send = Ref{Ptr{Cvoid}}(C_NULL)
const c_recv = Ref{Ptr{Cvoid}}(C_NULL)
const c_dbg = Ref{Ptr{Cvoid}}(C_NULL)
function __sslinit__()
    c_send[] = @cfunction(f_send, Cint, (Ptr{Cvoid}, Ptr{UInt8}, Csize_t))
    c_recv[] = @cfunction(f_recv, Cint, (Ptr{Cvoid}, Ptr{UInt8}, Csize_t))
    c_dbg[] = @cfunction(f_dbg, Cvoid, (Any, Cint, Ptr{UInt8}, Cint, Ptr{UInt8}))
end
