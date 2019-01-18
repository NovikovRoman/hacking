<?php

namespace AppBundle\Service\SlowAes;

class Aes
{
    public function toNumbers($s)
    {
        $ret = array();
        for ($i = 0; $i < strlen($s); $i += 2) {
            $ret[] = hexdec(substr($s, $i, 2));
        }
        return $ret;
    }

    public function toHex($args)
    {
        if (func_num_args() != 1 || !is_array($args)) {
            $args = func_get_args();
        }
        $ret = '';
        for ($i = 0; $i < count($args); $i++)
            $ret .= sprintf('%02x', $args[$i]);
        return $ret;
    }

    /*
     * Mode of Operation Encryption
     * bytesIn - Input String as array of bytes
     * mode - mode of type modeOfOperation
     * key - a number array of length 'size'
     * size - the bit length of the key
     * iv - the 128 bit number array Initialization Vector
     */
    /**
     * @param $bytesIn
     * @param $mode
     * @param $key
     * @param $iv
     * @return array
     * @throws \Exception
     */
    public function encrypt($bytesIn, $mode, $key, $iv)
    {
        $size = count($key);
        if (count($key) % 16) {
            throw new \Exception('Key length does not match specified size.');
        }
        if (count($iv) % 16) {
            throw new \Exception('iv length must be 128 bits.');
        }
        // the AES input/output
        $input = [];
        $ciphertext = [];
        $cipherOut = [];
        // char firstRound
        $firstRound = true;
        if ($mode == Config::MODE_CBC) {
            self::padBytesIn($bytesIn);
        }
        if ($bytesIn !== null) {
            for ($j = 0; $j < ceil(count($bytesIn) / 16); $j++) {
                $start = $j * 16;
                $end = $j * 16 + 16;
                if ($j * 16 + 16 > count($bytesIn)) {
                    $end = count($bytesIn);
                }
                $byteArray = $this->getBlock($bytesIn, $start, $end);
                if ($mode == Config::MODE_CFB) {
                    if ($firstRound) {
                        $output = self::encryptBlock($iv, $key, $size);
                        $firstRound = false;
                    } else {
                        $output = self::encryptBlock($input, $key, $size);
                    }
                    for ($i = 0; $i < 16; $i++) {
                        $ciphertext[$i] = $byteArray[$i] ^ $output[$i];
                    }
                    for ($k = 0; $k < $end - $start; $k++) {
                        array_push($cipherOut, $ciphertext[$k]);
                    }
                    $input = $ciphertext;
                } else if ($mode == Config::MODE_OFB) {
                    if ($firstRound) {
                        $output = self::encryptBlock($iv, $key, $size);
                        $firstRound = false;
                    } else {
                        $output = self::encryptBlock($input, $key, $size);
                    }
                    for ($i = 0; $i < 16; $i++) {
                        $ciphertext[$i] = $byteArray[$i] ^ $output[$i];
                    }
                    for ($k = 0; $k < $end - $start; $k++) {
                        array_push($cipherOut, $ciphertext[$k]);
                    }
                    $input = $output;
                } else if ($mode == Config::MODE_CBC) {
                    for ($i = 0; $i < 16; $i++) {
                        $input[$i] = $byteArray[$i] ^ (($firstRound) ? $iv[$i] : $ciphertext[$i]);
                    }
                    $firstRound = false;
                    $ciphertext = self::encryptBlock($input, $key, $size);
                    // always 16 bytes because of the padding for CBC
                    for ($k = 0; $k < 16; $k++) {
                        array_push($cipherOut, $ciphertext[$k]);
                    }
                }
            }
        }
        return $cipherOut;
    }

    /*
     * Mode of Operation Decryption
     * cipherIn - Encrypted String as array of bytes
     * originalsize - The unencrypted string length - required for CBC
     * mode - mode of type modeOfOperation
     * key - a number array of length 'size'
     * size - the bit length of the key
     * iv - the 128 bit number array Initialization Vector
     */
    /**
     * @param $cipherIn
     * @param $mode
     * @param $key
     * @param $iv
     * @return array
     * @throws \Exception
     */
    public function decrypt($cipherIn, $mode, $key, $iv)
    {
        $size = count($key);
        if (count($iv) % 16) {
            throw new \Exception('iv length must be 128 bits.');
        }
        // the AES input/output
        $input = [];
        $byteArray = [];
        $bytesOut = [];
        // char firstRound
        $firstRound = true;
        if ($cipherIn !== null) {
            for ($j = 0; $j < ceil(count($cipherIn) / 16); $j++) {
                $start = $j * 16;
                $end = $j * 16 + 16;
                if ($j * 16 + 16 > count($cipherIn)) {
                    $end = count($cipherIn);
                }
                $ciphertext = $this->getBlock($cipherIn, $start, $end);
                if ($mode == Config::MODE_CFB) {
                    if ($firstRound) {
                        $output = self::encryptBlock($iv, $key, $size);
                        $firstRound = false;
                    } else {
                        $output = self::encryptBlock($input, $key, $size);
                    }
                    for ($i = 0; $i < 16; $i++) {
                        $byteArray[$i] = $output[$i] ^ $ciphertext[$i];
                    }
                    for ($k = 0; $k < $end - $start; $k++) {
                        array_push($bytesOut, $byteArray[$k]);
                    }
                    $input = $ciphertext;
                } elseif ($mode == Config::MODE_OFB) {
                    if ($firstRound) {
                        $output = self::encryptBlock($iv, $key, $size);
                        $firstRound = false;
                    } else {
                        $output = self::encryptBlock($input, $key, $size);
                    }
                    for ($i = 0; $i < 16; $i++) {
                        $byteArray[$i] = $output[$i] ^ $ciphertext[$i];
                    }
                    for ($k = 0; $k < $end - $start; $k++) {
                        array_push($bytesOut, $byteArray[$k]);
                    }
                    $input = $output;
                } else if ($mode == Config::MODE_CBC) {
                    $output = self::decryptBlock($ciphertext, $key, $size);
                    for ($i = 0; $i < 16; $i++) {
                        $byteArray[$i] = (($firstRound) ? $iv[$i] : $input[$i]) ^ $output[$i];
                    }
                    $firstRound = false;
                    for ($k = 0; $k < $end - $start; $k++) {
                        array_push($bytesOut, $byteArray[$k]);
                    }
                    $input = $ciphertext;
                }
            }
        }
        return $bytesOut;
    }

    /* rotate the word eight bits to the left */
    private function rotate($word)
    {
        $c = $word[0];
        for ($i = 0; $i < 3; $i++) {
            $word[$i] = $word[$i + 1];
        }
        $word[3] = $c;
        return $word;
    }

    // Key Schedule Core
    private function core($word, $iteration)
    {
        /* rotate the 32-bit word 8 bits to the left */
        $word = $this->rotate($word);
        /* apply S-Box substitution on all 4 parts of the 32-bit word */
        for ($i = 0; $i < 4; ++$i) {
            $word[$i] = Config::$sbox[$word[$i]];
        }
        /* XOR the output of the rcon operation with i to the first part (leftmost) only */
        $word[0] = $word[0] ^ Config::$Rcon[$iteration];
        return $word;
    }

    /* Rijndael's key expansion
     * expands an 128,192,256 key into an 176,208,240 bytes key
     *
     * expandedKey is a pointer to an char array of large enough size
     * key is a pointer to a non-expanded key
     */
    private function expandKey($key, $size)
    {
        $expandedKeySize = (16 * (self::numberOfRounds($size) + 1));
        /* current expanded keySize, in bytes */
        $currentSize = 0;
        $rconIteration = 1;
        $t = [];   // temporary 4-byte variable
        $expandedKey = [];
        for ($i = 0; $i < $expandedKeySize; $i++) {
            $expandedKey[$i] = 0;
        }
        /* set the 16,24,32 bytes of the expanded key to the input key */
        for ($j = 0; $j < $size; $j++) {
            $expandedKey[$j] = $key[$j];
        }
        $currentSize += $size;
        while ($currentSize < $expandedKeySize) {
            /* assign the previous 4 bytes to the temporary value t */
            for ($k = 0; $k < 4; $k++) {
                $t[$k] = $expandedKey[($currentSize - 4) + $k];
            }
            /* every 16,24,32 bytes we apply the core schedule to t
             * and increment rconIteration afterwards
             */
            if ($currentSize % $size == 0) {
                $t = self::core($t, $rconIteration++);
            }
            /* For 256-bit keys, we add an extra sbox to the calculation */
            if ($size == Config::KEY_SIZE_256 && (($currentSize % $size) == 16)) {
                for ($l = 0; $l < 4; $l++) {
                    $t[$l] = Config::$sbox[$t[$l]];
                }
            }
            /* We XOR t with the four-byte block 16,24,32 bytes before the new expanded key.
             * This becomes the next four bytes in the expanded key.
             */
            for ($m = 0; $m < 4; $m++) {
                $expandedKey[$currentSize] = $expandedKey[$currentSize - $size] ^ $t[$m];
                $currentSize++;
            }
        }
        return $expandedKey;
    }

    // Adds (XORs) the round key to the state
    private function addRoundKey($state, $roundKey)
    {
        for ($i = 0; $i < 16; $i++) {
            $state[$i] = $state[$i] ^ $roundKey[$i];
        }
        return $state;
    }

    // Creates a round key from the given expanded key and the
    // position within the expanded key.
    private function createRoundKey($expandedKey, $roundKeyPointer)
    {
        $roundKey = [];
        for ($i = 0; $i < 4; $i++) {
            for ($j = 0; $j < 4; $j++) {
                $roundKey[$j * 4 + $i] = $expandedKey[$roundKeyPointer + $i * 4 + $j];
            }
        }
        return $roundKey;
    }

    /* substitute all the values from the state with the value in the SBox
     * using the state value as index for the SBox
     */
    private function subBytes($state, $isInv)
    {
        for ($i = 0; $i < 16; $i++) {
            $state[$i] = $isInv ? Config::$rsbox[$state[$i]] : Config::$sbox[$state[$i]];
        }
        return $state;
    }

    /* iterate over the 4 rows and call shiftRow() with that row */
    private function shiftRows($state, $isInv)
    {
        for ($i = 0; $i < 4; $i++) {
            $state = $this->shiftRow($state, $i * 4, $i, $isInv);
        }
        return $state;
    }

    /* each iteration shifts the row to the left by 1 */
    private function shiftRow($state, $statePointer, $nbr, $isInv)
    {
        for ($i = 0; $i < $nbr; $i++) {
            if ($isInv) {
                $tmp = $state[$statePointer + 3];
                for ($j = 3; $j > 0; $j--) {
                    $state[$statePointer + $j] = $state[$statePointer + $j - 1];
                }
                $state[$statePointer] = $tmp;
            } else {
                $tmp = $state[$statePointer];
                for ($j = 0; $j < 3; $j++) {
                    $state[$statePointer + $j] = $state[$statePointer + $j + 1];
                }
                $state[$statePointer + 3] = $tmp;
            }
        }
        return $state;
    }

    // galois multiplication of 8 bit characters a and b
    private function galois_multiplication($a, $b)
    {
        $p = 0;
        for ($counter = 0; $counter < 8; $counter++) {
            if (($b & 1) == 1) {
                $p ^= $a;
            }
            if ($p > 0x100) {
                $p ^= 0x100;
            }
            $hi_bit_set = ($a & 0x80); //keep p 8 bit
            $a <<= 1;
            if ($a > 0x100) {
                $a ^= 0x100;
            } //keep a 8 bit
            if ($hi_bit_set == 0x80) {
                $a ^= 0x1b;
            }

            if ($a > 0x100) {
                $a ^= 0x100;
            } //keep a 8 bit
            $b >>= 1;
            if ($b > 0x100) {
                $b ^= 0x100;
            } //keep b 8 bit
        }
        return $p;
    }

    private function mixColumns($state, $isInv)
    {
        $column = [];
        /* iterate over the 4 columns */
        for ($i = 0; $i < 4; $i++) {
            /* construct one column by iterating over the 4 rows */
            for ($j = 0; $j < 4; $j++) {
                $column[$j] = $state[($j * 4) + $i];
            }
            /* apply the mixColumn on one column */
            $column = $this->mixColumn($column, $isInv);
            /* put the values back into the state */
            for ($k = 0; $k < 4; $k++) {
                $state[($k * 4) + $i] = $column[$k];
            }
        }
        return $state;
    }

    // galois multipication of the 4x4 matrix
    private function mixColumn($column, $isInv)
    {
        if ($isInv) {
            $mult = [14, 9, 13, 11];
        } else {
            $mult = [2, 1, 1, 3];
        }
        $cpy = [];
        for ($i = 0; $i < 4; $i++) {
            $cpy[$i] = $column[$i];
        }
        $column[0] = self::galois_multiplication($cpy[0], $mult[0]) ^
            self::galois_multiplication($cpy[3], $mult[1]) ^
            self::galois_multiplication($cpy[2], $mult[2]) ^
            self::galois_multiplication($cpy[1], $mult[3]);
        $column[1] = self::galois_multiplication($cpy[1], $mult[0]) ^
            self::galois_multiplication($cpy[0], $mult[1]) ^
            self::galois_multiplication($cpy[3], $mult[2]) ^
            self::galois_multiplication($cpy[2], $mult[3]);
        $column[2] = self::galois_multiplication($cpy[2], $mult[0]) ^
            self::galois_multiplication($cpy[1], $mult[1]) ^
            self::galois_multiplication($cpy[0], $mult[2]) ^
            self::galois_multiplication($cpy[3], $mult[3]);
        $column[3] = self::galois_multiplication($cpy[3], $mult[0]) ^
            self::galois_multiplication($cpy[2], $mult[1]) ^
            self::galois_multiplication($cpy[1], $mult[2]) ^
            self::galois_multiplication($cpy[0], $mult[3]);
        return $column;
    }

    // applies the 4 operations of the forward round in sequence
    private function round($state, $roundKey)
    {
        $state = self::subBytes($state, false);
        $state = self::shiftRows($state, false);
        $state = self::mixColumns($state, false);
        $state = self::addRoundKey($state, $roundKey);
        return $state;
    }

    // applies the 4 operations of the inverse round in sequence
    private function invRound($state, $roundKey)
    {
        $state = self::shiftRows($state, true);
        $state = self::subBytes($state, true);
        $state = self::addRoundKey($state, $roundKey);
        $state = self::mixColumns($state, true);
        return $state;
    }

    /*
     * Perform the initial operations, the standard round, and the final operations
     * of the forward aes, creating a round key for each round
     */
    private function main($state, $expandedKey, $nbrRounds)
    {
        $state = self::addRoundKey($state, self::createRoundKey($expandedKey, 0));
        for ($i = 1; $i < $nbrRounds; $i++) {
            $state = self::round($state, self::createRoundKey($expandedKey, 16 * $i));
        }
        $state = self::subBytes($state, false);
        $state = self::shiftRows($state, false);
        $state = self::addRoundKey($state, self::createRoundKey($expandedKey, 16 * $nbrRounds));
        return $state;
    }

    /*
     * Perform the initial operations, the standard round, and the final operations
     * of the inverse aes, creating a round key for each round
     */
    private function invMain($state, $expandedKey, $nbrRounds)
    {
        $state = self::addRoundKey($state, self::createRoundKey($expandedKey, 16 * $nbrRounds));
        for ($i = $nbrRounds - 1; $i > 0; $i--) {
            $state = self::invRound($state, self::createRoundKey($expandedKey, 16 * $i));
        }
        $state = self::shiftRows($state, true);
        $state = self::subBytes($state, true);
        $state = self::addRoundKey($state, self::createRoundKey($expandedKey, 0));
        return $state;
    }

    private function numberOfRounds($size)
    {
        switch ($size) /* set the number of rounds */ {
            case Config::KEY_SIZE_128:
                $nbrRounds = 10;
                break;
            case Config::KEY_SIZE_192:
                $nbrRounds = 12;
                break;
            case Config::KEY_SIZE_256:
                $nbrRounds = 14;
                break;
            default:
                return null;
                break;
        }
        return $nbrRounds;
    }

    // encrypts a 128 bit input block against the given key of size specified
    private function encryptBlock($input, $key, $size)
    {
        $output = [];
        $block = []; /* the 128 bit block to encode */
        $nbrRounds = self::numberOfRounds($size);
        /* Set the block values, for the block:
         * a0,0 a0,1 a0,2 a0,3
         * a1,0 a1,1 a1,2 a1,3
         * a2,0 a2,1 a2,2 a2,3
         * a3,0 a3,1 a3,2 a3,3
         * the mapping order is a0,0 a1,0 a2,0 a3,0 a0,1 a1,1 ... a2,3 a3,3
         */
        /*iterate over the columns */
        for ($i = 0; $i < 4; $i++) {
            /* iterate over the rows */
            for ($j = 0; $j < 4; $j++) {
                $block[($i + ($j * 4))] = $input[($i * 4) + $j];
            }
        }

        /* expand the key into an 176, 208, 240 bytes key */
        $expandedKey = self::expandKey($key, $size); /* the expanded key */
        /* encrypt the block using the expandedKey */
        $block = self::main($block, $expandedKey, $nbrRounds);
        /* unmap the block again into the output */
        for ($k = 0; $k < 4; $k++) {
            /* iterate over the rows */
            for ($l = 0; $l < 4; $l++) {
                $output[($k * 4) + $l] = $block[($k + ($l * 4))];
            }
        }
        return $output;
    }

    // decrypts a 128 bit input block against the given key of size specified
    private function decryptBlock($input, $key, $size)
    {
        $output = [];
        $block = []; /* the 128 bit block to decode */
        $nbrRounds = self::numberOfRounds($size);
        /* Set the block values, for the block:
         * a0,0 a0,1 a0,2 a0,3
         * a1,0 a1,1 a1,2 a1,3
         * a2,0 a2,1 a2,2 a2,3
         * a3,0 a3,1 a3,2 a3,3
         * the mapping order is a0,0 a1,0 a2,0 a3,0 a0,1 a1,1 ... a2,3 a3,3
         */
        /* iterate over the columns */
        for ($i = 0; $i < 4; $i++) {
            /* iterate over the rows */
            for ($j = 0; $j < 4; $j++) {
                $block[($i + ($j * 4))] = $input[($i * 4) + $j];
            }
        }
        /* expand the key into an 176, 208, 240 bytes key */
        $expandedKey = self::expandKey($key, $size);
        /* decrypt the block using the expandedKey */
        $block = self::invMain($block, $expandedKey, $nbrRounds);
        /* unmap the block again into the output */
        for ($k = 0; $k < 4; $k++) {
            /* iterate over the rows */
            for ($l = 0; $l < 4; $l++) {
                $output[($k * 4) + $l] = $block[($k + ($l * 4))];
            }
        }
        return $output;
    }

    /*
     * END AES SECTION
     */

    /*
     * START MODE OF OPERATION SECTION
     */
    private function getBlock($bytesIn, $start, $end)
    {
        if ($end - $start > 16) {
            $end = $start + 16;
        }
        return array_slice($bytesIn, $start, $end - $start);
    }

    private function padBytesIn($data)
    {
        $len = count($data);
        $padByte = 16 - ($len % 16);
        for ($i = 0; $i < $padByte; $i++) {
            array_push($data, $padByte);
        }
        return $data;
    }
}
