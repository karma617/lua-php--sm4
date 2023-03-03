-- 原PHP版本：https://blog.csdn.net/weixin_42024325/article/details/128134887

local index = {}

local function __andBit(left, right) --与
    return (left == 1 and right == 1) and 1 or 0
end
local function __orBit(left, right) --或
    return (left == 1 or right == 1) and 1 or 0
end
local function __xorBit(left, right) --异或
    return (left + right) == 1 and 1 or 0
end
local function __base(left, right, op) --对每一位进行op运算，然后将值返回
    if left < right then
        left, right = right, left
    end
    local res = 0
    local shift = 1
    while left ~= 0 do
        local ra = left % 2 --取得每一位(最右边)
        local rb = right % 2
        res = shift * op(ra, rb) + res
        shift = shift * 2
        left = math.modf(left / 2) --右移
        right = math.modf(right / 2)
    end
    return res
end
-- 按位与
local function andOp(left, right)
    return __base(left, right, __andBit)
end
-- 按位异或
local function xorOp(left, right)
    return __base(left, right, __xorBit)
end
-- 按位或
local function orOp(left, right)
    return __base(left, right, __orBit)
end

local function notOp(left)
    return left > 0 and -(left + 1) or -left - 1
end

-- 按位左移
local function lShiftOp(left, num) --left左移num位
    return left * (2 ^ num)
end
-- 按位右移
local function rShiftOp(left, num) --right右移num位
    return math.floor(left / (2 ^ num))
end


local SM4_CK = {
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
};
local SM4_SBOX = {
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
}
local SM4_FK = { 0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC };

local rk = {}
local _block_size = 16

-- string 2 bytes
local function unpackStr(str)
    local result = {}
    for i = 1, #str do
        result[i] = string.byte(str, i)
    end
    return result
end

local function sm4Rotl32(buf, n)
    return orOp(andOp(lShiftOp(buf, n), 0xffffffff), rShiftOp(buf, 32 - n))
end
-- 密钥key键表
local function sM4KeySchedule(key)
    local key = unpackStr(key)
    local round_key = {}
    for i = 0, 3 do
        round_key[i + 1] = xorOp(SM4_FK[i + 1], orOp(
            lShiftOp(key[4 * i + 1], 24),
            orOp(
                lShiftOp(key[4 * i + 1 + 1], 16),
                orOp(
                    lShiftOp(key[4 * i + 1 + 2], 8),
                    key[4 * i + 1 + 3]
                )
            )
        ))
    end
    for j = 0, 31 do
        local tmp = xorOp(xorOp(xorOp(round_key[j + 1 + 1], round_key[j + 1 + 2]), round_key[j + 1 + 3]), SM4_CK[j + 1])
        local buf = orOp(
            orOp(
                orOp(
                    lShiftOp(SM4_SBOX[andOp(rShiftOp(tmp, 24), 0xff) + 1], 24),
                    lShiftOp(SM4_SBOX[andOp(rShiftOp(tmp, 16), 0xff) + 1], 16)
                ), lShiftOp(SM4_SBOX[andOp(rShiftOp(tmp, 8), 0xff) + 1], 8)
            ), SM4_SBOX[andOp(tmp, 0xff) + 1]
        )
        round_key[j + 4 + 1] = xorOp(
            round_key[j + 1],
            xorOp(
                xorOp(buf, sm4Rotl32(buf, 13)), sm4Rotl32(buf, 23)
            )
        )
        rk[j + 1] = round_key[j + 4 + 1]
    end
    return rk
end
-- 分割数组
local function array_chunk(arr, size)
    local chunks = {}
    local chunk_index = 1
    for i = 1, #arr, size do
        chunks[chunk_index] = {}
        for j = i, i + size - 1 do
            if arr[j] then
                table.insert(chunks[chunk_index], arr[j])
            end
        end
        chunk_index = chunk_index + 1
    end
    return chunks
end
-- bytes转string
local function bytesToString(bytes)
    return string.format(string.rep('%c', #bytes), table.unpack(bytes));
end

local function array_slice(array, offset, length)
    local slice = {}
    local start_index = offset + 1
    local end_index = offset + length

    for i = start_index, end_index do
        if array[i] ~= nil then
            table.insert(slice, array[i])
        end
    end

    return slice
end
-- 填充
local function pad(data)
    local bytes = unpackStr(data)
    local rem = _block_size - #bytes % _block_size;
    for i = 1, rem do
        table.insert(bytes, rem)
    end
    return bytes
end
-- 逆填充
local function un_pad(string)
    local bytes = unpackStr(string)
    local rem = bytes[#bytes]
    bytes = array_slice(bytes, 0, #bytes - rem)
    return bytesToString(bytes)
end
-- 加密
local function sM4Encrypt(plainText)
    local x = {}
    for i = 0, 3 do
        x[i + 1] = orOp(orOp(
            orOp(
                lShiftOp(plainText[i * 4 + 1], 24),
                lShiftOp(plainText[i * 4 + 1 + 1], 16)
            ), lShiftOp(plainText[i * 4 + 1 + 2], 8)), plainText[i * 4 + 1 + 3])
    end

    for j = 0, 31 do
        local tmp = xorOp(xorOp(xorOp(x[j + 1 + 1], x[j + 1 + 2]), x[j + 1 + 3]), rk[j + 1])
        local buf = orOp(
            orOp(
                orOp(
                    lShiftOp(SM4_SBOX[andOp(rShiftOp(tmp, 24), 0xff) + 1], 24),
                    lShiftOp(SM4_SBOX[andOp(rShiftOp(tmp, 16), 0xff) + 1], 16)
                ), lShiftOp(SM4_SBOX[andOp(rShiftOp(tmp, 8), 0xff) + 1], 8)
            ), SM4_SBOX[andOp(tmp, 0xff) + 1]
        )
        x[j + 4 + 1] = xorOp(
            x[j + 1],
            xorOp(xorOp(xorOp(xorOp(buf, sm4Rotl32(buf, 2)), sm4Rotl32(buf, 10)), sm4Rotl32(buf, 18)), sm4Rotl32(buf, 24))
        )
    end
    local cipherText = {}
    for i = 0, 3 do
        cipherText[i * 4 + 1] = andOp(rShiftOp(x[36 - i], 24), 0xff)
        cipherText[i * 4 + 1 + 1] = andOp(rShiftOp(x[36 - i], 16), 0xff)
        cipherText[i * 4 + 1 + 2] = andOp(rShiftOp(x[36 - i], 8), 0xff)
        cipherText[i * 4 + 1 + 3] = andOp(x[36 - i], 0xff)
    end
    return bytesToString(cipherText)
end
-- 解密
local function sM4Decrypt(plainText)
    local x = {}
    for i = 0, 3 do
        x[i + 1] = orOp(orOp(
            orOp(
                lShiftOp(plainText[i * 4 + 1], 24),
                lShiftOp(plainText[i * 4 + 1 + 1], 16)
            ), lShiftOp(plainText[i * 4 + 1 + 2], 8)), plainText[i * 4 + 1 + 3])
    end
    for j = 0, 31 do
        local tmp = xorOp(xorOp(xorOp(x[j + 1 + 1], x[j + 1 + 2]), x[j + 1 + 3]), rk[32 - j])
        local buf = orOp(
            orOp(
                orOp(
                    lShiftOp(SM4_SBOX[andOp(rShiftOp(tmp, 24), 0xff) + 1], 24),
                    lShiftOp(SM4_SBOX[andOp(rShiftOp(tmp, 16), 0xff) + 1], 16)
                ), lShiftOp(SM4_SBOX[andOp(rShiftOp(tmp, 8), 0xff) + 1], 8)
            ), SM4_SBOX[andOp(tmp, 0xff) + 1]
        )
        x[j + 4 + 1] = xorOp(
            x[j + 1],
            xorOp(xorOp(xorOp(xorOp(buf, sm4Rotl32(buf, 2)), sm4Rotl32(buf, 10)), sm4Rotl32(buf, 18)), sm4Rotl32(buf, 24))
        )
    end
    local cipherText = {}
    for i = 0, 3 do
        cipherText[i * 4 + 1] = andOp(rShiftOp(x[36 - i], 24), 0xff)
        cipherText[i * 4 + 1 + 1] = andOp(rShiftOp(x[36 - i], 16), 0xff)
        cipherText[i * 4 + 1 + 2] = andOp(rShiftOp(x[36 - i], 8), 0xff)
        cipherText[i * 4 + 1 + 3] = andOp(x[36 - i], 0xff)
    end
    return bytesToString(cipherText)
end

-- 对字符串加密
function index:sm4_encode()
    local key = '743ee4a18e3210af'
    sM4KeySchedule(key)
    local str = 'hello word'
    local bytes = pad(str)
    local chunks = array_chunk(bytes, _block_size)
    local ciphertext = "";
    for _, chunk in pairs(chunks) do
        ciphertext = ciphertext .. sM4Encrypt(chunk)
    end
    dump(ngx.encode_base64(ciphertext))
end

-- 对字符串解密
function index:sm4_decode()
    local key = '743ee4a18e3210af'
    local str = ngx.decode_base64('f0qhGmgsaE9CO5kPLdTxlQ==')
    if #str < 0 or (#str % _block_size ~= 0) then
        return false;
    end
    sM4KeySchedule(key)
    local bytes = unpackStr(str)
    local chunks = array_chunk(bytes, _block_size)
    local ciphertext = "";
    for _, chunk in pairs(chunks) do
        ciphertext = ciphertext .. sM4Decrypt(chunk)
    end
    ciphertext = un_pad(ciphertext)
    dump(ciphertext)
end

return index
