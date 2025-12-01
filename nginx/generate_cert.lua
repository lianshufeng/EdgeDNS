local ssl  = require "ngx.ssl"
local dict = ngx.shared.certs

local domain = ssl.server_name()
if not domain then
    ngx.log(ngx.ERR, "NO SNI (ssl.server_name is nil)")
    return
end

--------------------------------------------------------
-- 从 shared dict 读缓存（直接缓存 DER 字符串）
--------------------------------------------------------
local cert_der = dict:get(domain .. ":cert_der")
local key_der  = dict:get(domain .. ":key_der")

if cert_der and key_der then
    ssl.clear_certs()

    local ok, err = ssl.set_der_cert(cert_der)
    if not ok then
        ngx.log(ngx.ERR, "set_der_cert (cached) failed: ", err)
        return
    end

    ok, err = ssl.set_der_priv_key(key_der)
    if not ok then
        ngx.log(ngx.ERR, "set_der_priv_key (cached) failed: ", err)
        return
    end

    return
end

--------------------------------------------------------
-- 没有缓存，开始动态生成证书
--------------------------------------------------------
local tmp_dir = "/tmp/mitm"
os.execute("mkdir -p " .. tmp_dir)

local key_pem_path = tmp_dir .. "/" .. domain .. ".key"
local csr_pem_path = tmp_dir .. "/" .. domain .. ".csr"
local crt_pem_path = tmp_dir .. "/" .. domain .. ".crt"
local ext_path     = tmp_dir .. "/" .. domain .. ".ext"
local srl_path     = tmp_dir .. "/ca.srl"

--------------------------------------------------------
-- 写 extfile，必须有 [ req_ext ] + subjectAltName
--------------------------------------------------------
do
    local f, err = io.open(ext_path, "w")
    if not f then
        ngx.log(ngx.ERR, "open ext file failed: ", err)
        return
    end
    f:write("[ req_ext ]\n")
    f:write("subjectAltName = DNS:" .. domain .. "\n")
    f:close()
end

--------------------------------------------------------
-- 生成私钥
--------------------------------------------------------
os.execute("openssl genrsa -out " .. key_pem_path .. " 2048")

--------------------------------------------------------
-- 生成 CSR
--------------------------------------------------------
os.execute("openssl req -new -key " .. key_pem_path ..
           " -out " .. csr_pem_path ..
           " -subj \"/CN=" .. domain .. "\"")

--------------------------------------------------------
-- 用 RootCA 签发证书
-- 重点：-CAserial + -CAcreateserial 写到可写目录 /tmp/mitm
--------------------------------------------------------
local x509_cmd = "openssl x509 -req -in " .. csr_pem_path ..
    " -CA /etc/nginx/ssl/myRootCA.pem" ..
    " -CAkey /etc/nginx/ssl/myRootCA.key" ..
    " -CAserial " .. srl_path .. " -CAcreateserial" ..
    " -out " .. crt_pem_path ..
    " -days 365 -sha256 -extfile " .. ext_path ..
    " -extensions req_ext"

os.execute(x509_cmd)

--------------------------------------------------------
-- 读取生成好的 PEM 文件
--------------------------------------------------------
local function read_file(path)
    local f, err = io.open(path, "rb")
    if not f then
        ngx.log(ngx.ERR, "read_file open failed: ", path, " err: ", err)
        return nil
    end
    local d = f:read("*a")
    f:close()
    return d
end

local cert_pem = read_file(crt_pem_path)
local key_pem  = read_file(key_pem_path)

if not cert_pem or cert_pem == "" then
    ngx.log(ngx.ERR, "cert_pem is empty, x509 sign may have failed")
    return
end
if not key_pem or key_pem == "" then
    ngx.log(ngx.ERR, "key_pem is empty, genrsa may have failed")
    return
end

--------------------------------------------------------
-- 把 PEM 转成 DER（string）
--------------------------------------------------------
local err
cert_der, err = ssl.cert_pem_to_der(cert_pem)
if not cert_der then
    ngx.log(ngx.ERR, "cert_pem_to_der failed: ", err)
    return
end

key_der, err = ssl.priv_key_pem_to_der(key_pem)
if not key_der then
    ngx.log(ngx.ERR, "priv_key_pem_to_der failed: ", err)
    return
end

--------------------------------------------------------
-- 写入缓存（缓存 DER，避免下次再转）
--------------------------------------------------------
dict:set(domain .. ":cert_der", cert_der, 3600)
dict:set(domain .. ":key_der",  key_der,  3600)

--------------------------------------------------------
-- 设置到当前连接
--------------------------------------------------------
ssl.clear_certs()

local ok, set_err = ssl.set_der_cert(cert_der)
if not ok then
    ngx.log(ngx.ERR, "set_der_cert failed: ", set_err)
    return
end

ok, set_err = ssl.set_der_priv_key(key_der)
if not ok then
    ngx.log(ngx.ERR, "set_der_priv_key failed: ", set_err)
    return
end
