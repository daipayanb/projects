from Crypto.Cipher import AES


def aes_enc(inputblock, key):
    cipher = AES.new(key, AES.MODE_ECB)
    cipher_text = cipher.encrypt(inputblock)
    return cipher_text


def invert_bit(inputb, b):
    inputblock = ''.join(inputb)
    outputblock = [inputblock[i] if b != i else ('0' if inputblock[i] == '1' else '1') for i in
                   range(0, len(inputblock))]
    return outputblock


def bytes2bit(inputblock):
    inplist = [bin(int(b))[2:].zfill(8) for b in inputblock]
    return inplist


def bit2bytes(inputb):
    inputl = ''.join(inputb)
    output = b''
    for i in range(0, int(len(inputl) / 8)):
        item = inputl[i * 8:i * 8 + 8]
        number = int(str(item), 2)
        output += bytes([number])
    return output


def findbitdiff(input1, input2):
    diff = [1 if x != y else 0 for x, y in zip(''.join(bytes2bit(input1)), ''.join(bytes2bit(input2)))]
    return sum(diff)


def aes_input_av_test(inputblock, key, bitlist):
    diff_list = []

    inputbytes = bytes.fromhex(inputblock)
    keybytes = bytes.fromhex(key)
    originalcipher = aes_enc(inputbytes, keybytes)

    for b in bitlist:
        newinputblock = bytes2bit(inputbytes)
        newogcipher = bytes2bit(originalcipher)
        newinput = invert_bit(newinputblock, b)

        n = bit2bytes(newinput)

        newcipher = aes_enc(n, keybytes)

        numbitdifferences = findbitdiff(originalcipher, newcipher)

        diff_list.append(numbitdifferences)

    return diff_list


def aes_key_av_test(inputblock, key, bitlist):
    diff_list = []

    inputbytes = bytes.fromhex(inputblock)
    keybytes = bytes.fromhex(key)
    originalcipher = aes_enc(inputbytes, keybytes)

    for b in bitlist:
        newkeybytes = bytes2bit(keybytes)
        newogcipher = bytes2bit(originalcipher)

        newkey = invert_bit(newkeybytes, b)

        n = bit2bytes(newkey)
        newcipher = aes_enc(inputbytes, n)

        numbitdifferences = findbitdiff(originalcipher, newcipher)

        diff_list.append(numbitdifferences)

    return diff_list


