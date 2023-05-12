<?php


namespace Drupal\miniorange_saml;

class AESEncryption
{
    public static function encrypt_data($LF, $eQ)
    {
        $eQ = openssl_digest($eQ, "\x73\x68\x61\62\65\x36");
        $XF = "\x41\105\x53\x2d\61\x32\70\x2d\103\102\103";
        $Qy = openssl_cipher_iv_length($XF);
        $zb = openssl_random_pseudo_bytes($Qy);
        $TW = openssl_encrypt($LF, $XF, $eQ, OPENSSL_RAW_DATA || OPENSSL_ZERO_PADDING, $zb);
        return base64_encode($zb . $TW);
    }
    public static function decrypt_data($LF, $eQ, $XF = "\101\105\x53\x2d\61\62\x38\55\103\x42\x43")
    {
        if (!($LF != null)) {
            goto gs;
        }
        $cz = base64_decode($LF);
        $eQ = openssl_digest($eQ, "\163\x68\x61\x32\65\x36");
        $Qy = openssl_cipher_iv_length($XF);
        $zb = substr($cz, 0, $Qy);
        $LF = substr($cz, $Qy);
        $QM = openssl_decrypt($LF, $XF, $eQ, OPENSSL_RAW_DATA || OPENSSL_ZERO_PADDING, $zb);
        return $QM;
        gs:
    }
}
