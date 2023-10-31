<?php


namespace Drupal\miniorange_saml;

class AESEncryption
{
    public static function encrypt_data($F9, $yQ)
    {
        $yQ = openssl_digest($yQ, "\163\x68\x61\x32\x35\66");
        $gm = "\x41\x45\x53\x2d\x31\x32\x38\55\x43\x42\103";
        $lZ = openssl_cipher_iv_length($gm);
        $fw = openssl_random_pseudo_bytes($lZ);
        $EG = openssl_encrypt($F9, $gm, $yQ, OPENSSL_RAW_DATA || OPENSSL_ZERO_PADDING, $fw);
        return base64_encode($fw . $EG);
    }
    public static function decrypt_data($F9, $yQ, $gm = "\x41\x45\x53\55\61\62\70\x2d\x43\102\103")
    {
        if (!($F9 != null)) {
            goto aB;
        }
        $du = base64_decode($F9);
        $yQ = openssl_digest($yQ, "\x73\x68\141\62\x35\66");
        $lZ = openssl_cipher_iv_length($gm);
        $fw = substr($du, 0, $lZ);
        $F9 = substr($du, $lZ);
        $VS = openssl_decrypt($F9, $gm, $yQ, OPENSSL_RAW_DATA || OPENSSL_ZERO_PADDING, $fw);
        return $VS;
        aB:
    }
}
