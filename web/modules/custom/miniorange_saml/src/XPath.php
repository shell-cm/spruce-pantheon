<?php


namespace Drupal\miniorange_saml;

class XPath
{
    const ALPHANUMERIC = "\134\167\x5c\x64";
    const NUMERIC = "\x5c\144";
    const LETTERS = "\134\167";
    const EXTENDED_ALPHANUMERIC = "\x5c\167\x5c\144\x5c\x73\x5c\55\x5f\x3a\x5c\x2e";
    const SINGLE_QUOTE = "\47";
    const DOUBLE_QUOTE = "\x22";
    const ALL_QUOTES = "\133\x27\42\135";
    public static function filterAttrValue($Ox, $u3 = self::ALL_QUOTES)
    {
        return preg_replace("\43" . $u3 . "\x23", '', $Ox);
    }
    public static function filterAttrName($KC, $YM = self::EXTENDED_ALPHANUMERIC)
    {
        return preg_replace("\43\x5b\x5e" . $YM . "\x5d\x23", '', $KC);
    }
}
