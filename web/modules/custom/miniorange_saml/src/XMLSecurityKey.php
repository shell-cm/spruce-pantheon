<?php


namespace Drupal\miniorange_saml;

use DOMDocument;
use DOMElement;
use DOMXPath;
use Exception;
class XMLSecurityKey
{
    const TRIPLEDES_CBC = "\150\164\x74\x70\72\57\x2f\167\167\x77\56\167\x33\x2e\x6f\162\x67\57\62\x30\60\61\57\x30\64\x2f\x78\155\x6c\x65\156\x63\43\x74\x72\x69\x70\x6c\x65\x64\145\x73\x2d\143\142\143";
    const AES128_CBC = "\150\x74\164\160\72\57\x2f\x77\167\x77\x2e\x77\x33\56\157\x72\x67\57\x32\x30\x30\x31\57\x30\x34\57\170\155\x6c\145\156\x63\x23\x61\x65\x73\x31\62\x38\55\143\142\143";
    const AES192_CBC = "\x68\x74\164\160\x3a\x2f\x2f\167\167\x77\x2e\167\63\x2e\x6f\x72\x67\57\x32\x30\x30\x31\57\x30\x34\57\170\x6d\154\x65\x6e\143\43\x61\x65\163\x31\71\62\55\143\x62\x63";
    const AES256_CBC = "\150\164\x74\160\72\x2f\57\167\167\167\x2e\167\x33\56\157\x72\147\57\x32\x30\x30\61\57\x30\64\x2f\x78\x6d\154\145\156\x63\x23\x61\145\163\62\x35\x36\55\x63\x62\x63";
    const AES128_GCM = "\150\x74\164\160\x3a\57\57\167\167\x77\x2e\x77\x33\x2e\x6f\162\147\x2f\x32\60\60\71\x2f\170\x6d\154\145\x6e\x63\x31\x31\43\141\x65\x73\x31\x32\x38\x2d\147\143\x6d";
    const AES192_GCM = "\150\x74\164\160\72\57\57\x77\167\x77\x2e\x77\63\x2e\157\162\147\x2f\62\60\60\x39\x2f\170\155\x6c\145\156\143\x31\x31\43\141\x65\163\61\x39\62\x2d\x67\143\155";
    const AES256_GCM = "\x68\x74\164\x70\x3a\x2f\x2f\x77\x77\x77\x2e\x77\63\x2e\157\162\147\57\62\x30\60\71\x2f\170\155\x6c\145\156\143\x31\61\x23\x61\145\x73\x32\x35\x36\55\x67\143\x6d";
    const RSA_1_5 = "\x68\164\x74\160\x3a\57\x2f\x77\167\167\x2e\x77\x33\56\x6f\162\147\x2f\62\x30\60\61\x2f\x30\64\57\x78\155\x6c\x65\156\x63\x23\x72\163\141\x2d\61\137\65";
    const RSA_OAEP_MGF1P = "\150\x74\x74\160\72\x2f\x2f\x77\x77\x77\56\167\63\56\x6f\162\x67\x2f\x32\60\60\x31\x2f\60\x34\x2f\170\155\154\x65\x6e\143\x23\x72\x73\x61\x2d\x6f\x61\145\160\55\x6d\x67\146\61\x70";
    const RSA_OAEP = "\x68\164\x74\160\x3a\x2f\57\167\x77\x77\56\167\63\x2e\157\162\147\57\x32\x30\x30\71\x2f\x78\155\x6c\x65\x6e\x63\61\61\x23\162\x73\x61\55\157\141\145\x70";
    const DSA_SHA1 = "\x68\164\x74\x70\x3a\57\57\167\x77\167\56\x77\63\x2e\157\x72\147\57\62\60\x30\x30\x2f\60\71\57\170\x6d\154\x64\163\151\x67\x23\x64\163\x61\55\x73\150\141\x31";
    const RSA_SHA1 = "\150\164\164\160\x3a\x2f\57\x77\167\167\x2e\x77\63\56\x6f\162\x67\x2f\x32\x30\60\x30\57\x30\x39\x2f\170\155\154\144\x73\x69\x67\43\162\x73\141\55\x73\x68\141\x31";
    const RSA_SHA256 = "\x68\x74\x74\x70\72\57\57\x77\167\x77\x2e\x77\x33\56\x6f\x72\x67\x2f\62\x30\x30\61\57\x30\64\x2f\170\x6d\x6c\x64\x73\x69\x67\x2d\155\x6f\x72\145\x23\x72\x73\x61\x2d\163\150\141\x32\x35\66";
    const RSA_SHA384 = "\150\x74\x74\160\72\57\x2f\x77\167\167\56\x77\x33\x2e\157\x72\x67\57\x32\60\60\61\57\x30\64\57\170\155\154\144\x73\x69\x67\x2d\x6d\x6f\x72\145\43\162\163\141\55\x73\x68\141\x33\70\x34";
    const RSA_SHA512 = "\x68\x74\164\x70\72\x2f\57\x77\167\x77\56\167\x33\x2e\x6f\162\x67\57\x32\x30\60\61\x2f\x30\x34\57\x78\x6d\154\144\163\x69\147\55\x6d\157\x72\x65\x23\162\163\141\x2d\x73\150\x61\x35\x31\x32";
    const HMAC_SHA1 = "\x68\164\x74\160\72\57\x2f\167\x77\x77\x2e\x77\63\x2e\157\162\147\57\x32\x30\60\60\x2f\60\71\57\x78\155\154\144\x73\151\147\x23\150\x6d\x61\x63\x2d\163\x68\141\x31";
    const AUTHTAG_LENGTH = 16;
    private $cryptParams = array();
    public $type = 0;
    public $key = null;
    public $passphrase = '';
    public $iv = null;
    public $name = null;
    public $keyChain = null;
    public $isEncrypted = false;
    public $encryptedCtx = null;
    public $guid = null;
    private $x509Certificate = null;
    private $X509Thumbprint = null;
    public function __construct($O_, $uF = null)
    {
        switch ($O_) {
            case self::TRIPLEDES_CBC:
                $this->cryptParams["\x6c\151\142\162\x61\162\x79"] = "\x6f\160\145\x6e\x73\x73\154";
                $this->cryptParams["\143\x69\x70\x68\145\x72"] = "\x64\145\x73\55\145\144\145\63\x2d\x63\142\143";
                $this->cryptParams["\x74\x79\x70\145"] = "\163\171\x6d\155\x65\164\x72\x69\x63";
                $this->cryptParams["\155\145\164\x68\x6f\x64"] = "\x68\x74\x74\160\72\57\57\x77\167\x77\56\x77\63\56\x6f\x72\x67\57\x32\60\60\61\x2f\x30\64\x2f\170\x6d\x6c\145\156\143\43\164\x72\151\160\154\x65\x64\145\163\x2d\x63\142\143";
                $this->cryptParams["\153\x65\171\x73\151\172\x65"] = 24;
                $this->cryptParams["\142\154\157\x63\x6b\x73\x69\x7a\145"] = 8;
                goto bR;
            case self::AES128_CBC:
                $this->cryptParams["\x6c\151\x62\x72\141\162\x79"] = "\157\160\145\x6e\163\163\154";
                $this->cryptParams["\x63\151\160\x68\145\162"] = "\x61\145\x73\55\61\62\x38\x2d\143\142\143";
                $this->cryptParams["\164\171\x70\x65"] = "\163\171\x6d\x6d\145\164\x72\x69\143";
                $this->cryptParams["\155\145\x74\x68\157\144"] = "\x68\x74\x74\x70\72\x2f\57\x77\x77\167\56\167\x33\56\x6f\x72\147\x2f\62\x30\x30\x31\57\x30\64\57\170\x6d\x6c\145\x6e\x63\x23\141\145\163\61\62\x38\x2d\143\142\143";
                $this->cryptParams["\x6b\145\171\x73\x69\172\145"] = 16;
                $this->cryptParams["\x62\x6c\x6f\x63\x6b\163\x69\172\x65"] = 16;
                goto bR;
            case self::AES192_CBC:
                $this->cryptParams["\154\x69\x62\x72\x61\x72\x79"] = "\x6f\160\145\156\x73\x73\x6c";
                $this->cryptParams["\x63\151\x70\150\145\162"] = "\x61\x65\163\55\61\71\x32\55\143\142\143";
                $this->cryptParams["\164\x79\x70\x65"] = "\163\171\x6d\x6d\145\164\162\151\x63";
                $this->cryptParams["\155\145\x74\x68\157\x64"] = "\x68\164\x74\160\x3a\57\x2f\x77\x77\x77\56\x77\63\x2e\157\162\147\x2f\x32\60\60\x31\x2f\x30\x34\57\170\155\x6c\x65\156\x63\x23\141\x65\x73\61\71\x32\x2d\143\x62\x63";
                $this->cryptParams["\x6b\145\171\x73\x69\172\145"] = 24;
                $this->cryptParams["\142\x6c\x6f\143\153\x73\151\x7a\x65"] = 16;
                goto bR;
            case self::AES256_CBC:
                $this->cryptParams["\154\x69\x62\162\x61\x72\x79"] = "\x6f\x70\145\x6e\x73\x73\x6c";
                $this->cryptParams["\x63\151\160\150\x65\162"] = "\x61\x65\163\x2d\x32\x35\x36\55\x63\142\x63";
                $this->cryptParams["\x74\x79\160\145"] = "\163\x79\x6d\155\x65\x74\x72\151\x63";
                $this->cryptParams["\x6d\x65\x74\x68\157\144"] = "\x68\x74\x74\x70\72\57\57\167\167\167\56\x77\63\56\157\x72\147\x2f\x32\60\60\61\57\60\64\57\170\x6d\x6c\x65\156\143\43\141\x65\163\62\x35\66\x2d\143\142\143";
                $this->cryptParams["\x6b\145\x79\163\151\172\145"] = 32;
                $this->cryptParams["\142\x6c\x6f\143\x6b\163\x69\x7a\145"] = 16;
                goto bR;
            case self::AES128_GCM:
                $this->cryptParams["\154\x69\142\162\x61\x72\x79"] = "\157\x70\x65\x6e\163\x73\154";
                $this->cryptParams["\143\151\160\x68\145\162"] = "\141\145\163\x2d\61\62\70\x2d\x67\143\155";
                $this->cryptParams["\164\x79\x70\145"] = "\x73\x79\x6d\155\145\164\162\x69\143";
                $this->cryptParams["\x6d\145\x74\150\x6f\144"] = "\150\164\164\160\x3a\57\57\167\167\x77\56\x77\x33\x2e\x6f\162\x67\57\x32\x30\60\x39\57\170\x6d\154\x65\x6e\143\x31\61\x23\x61\x65\x73\61\62\70\55\147\143\155";
                $this->cryptParams["\x6b\145\x79\x73\151\172\x65"] = 16;
                $this->cryptParams["\x62\154\157\143\x6b\x73\151\x7a\x65"] = 16;
                goto bR;
            case self::AES192_GCM:
                $this->cryptParams["\154\151\x62\162\x61\162\171"] = "\157\160\x65\156\163\x73\154";
                $this->cryptParams["\143\x69\x70\x68\145\x72"] = "\141\x65\163\x2d\61\71\62\55\x67\143\x6d";
                $this->cryptParams["\x74\171\160\x65"] = "\163\171\x6d\155\145\164\162\151\x63";
                $this->cryptParams["\155\145\x74\x68\157\144"] = "\x68\x74\164\160\72\57\x2f\x77\x77\167\x2e\167\63\x2e\157\162\x67\x2f\62\x30\x30\71\x2f\170\155\x6c\145\x6e\143\x31\61\43\x61\x65\163\61\71\x32\x2d\147\143\x6d";
                $this->cryptParams["\153\x65\x79\x73\x69\172\x65"] = 24;
                $this->cryptParams["\142\x6c\157\143\x6b\x73\151\x7a\145"] = 16;
                goto bR;
            case self::AES256_GCM:
                $this->cryptParams["\154\151\x62\x72\x61\162\171"] = "\x6f\160\145\x6e\163\x73\154";
                $this->cryptParams["\143\151\160\150\145\162"] = "\x61\x65\x73\55\x32\65\66\55\147\143\155";
                $this->cryptParams["\164\x79\x70\145"] = "\163\x79\155\155\145\164\x72\151\143";
                $this->cryptParams["\155\x65\x74\150\157\144"] = "\x68\164\164\160\x3a\x2f\x2f\167\167\x77\x2e\167\x33\x2e\157\162\x67\x2f\62\60\x30\71\57\170\x6d\154\145\156\143\61\61\x23\x61\x65\x73\x32\x35\x36\x2d\x67\143\155";
                $this->cryptParams["\153\145\x79\163\x69\172\145"] = 32;
                $this->cryptParams["\x62\x6c\157\143\153\163\151\172\x65"] = 16;
                goto bR;
            case self::RSA_1_5:
                $this->cryptParams["\154\151\142\162\141\162\x79"] = "\x6f\x70\x65\156\163\x73\x6c";
                $this->cryptParams["\160\141\144\144\151\x6e\147"] = OPENSSL_PKCS1_PADDING;
                $this->cryptParams["\155\x65\x74\150\157\144"] = "\x68\x74\x74\x70\72\57\x2f\167\x77\167\x2e\167\x33\56\157\162\x67\57\62\60\x30\61\x2f\x30\64\x2f\170\x6d\x6c\145\x6e\x63\x23\x72\x73\x61\x2d\x31\x5f\65";
                if (!(is_array($uF) && !empty($uF["\x74\x79\160\145"]))) {
                    goto Fd;
                }
                if (!($uF["\x74\171\x70\145"] == "\160\165\x62\154\x69\x63" || $uF["\x74\171\x70\145"] == "\160\x72\151\x76\x61\164\145")) {
                    goto Bb;
                }
                $this->cryptParams["\164\x79\160\x65"] = $uF["\164\x79\160\145"];
                goto bR;
                Bb:
                Fd:
                throw new Exception("\103\145\162\164\x69\x66\151\x63\x61\164\x65\x20\42\x74\171\160\x65\42\40\50\x70\x72\151\x76\141\164\145\57\160\x75\142\x6c\151\x63\x29\x20\155\x75\163\164\x20\142\x65\x20\160\x61\x73\x73\145\144\40\166\151\141\40\160\141\x72\141\155\x65\x74\x65\x72\163");
            case self::RSA_OAEP_MGF1P:
                $this->cryptParams["\154\x69\142\162\x61\162\x79"] = "\x6f\x70\x65\x6e\x73\163\154";
                $this->cryptParams["\160\x61\x64\144\151\156\147"] = OPENSSL_PKCS1_OAEP_PADDING;
                $this->cryptParams["\155\145\164\x68\157\x64"] = "\150\x74\164\x70\x3a\x2f\x2f\167\x77\167\56\x77\63\x2e\157\162\x67\57\x32\x30\60\x31\x2f\x30\x34\x2f\x78\155\154\145\156\x63\43\x72\163\141\x2d\x6f\141\145\160\x2d\x6d\x67\146\61\x70";
                $this->cryptParams["\x68\x61\163\x68"] = null;
                if (!(is_array($uF) && !empty($uF["\x74\x79\x70\145"]))) {
                    goto FE;
                }
                if (!($uF["\164\x79\160\145"] == "\x70\165\142\x6c\151\x63" || $uF["\164\x79\160\145"] == "\x70\162\151\166\141\164\x65")) {
                    goto tA;
                }
                $this->cryptParams["\164\171\x70\145"] = $uF["\164\171\160\x65"];
                goto bR;
                tA:
                FE:
                throw new Exception("\x43\145\162\164\x69\x66\x69\143\x61\164\145\x20\42\x74\171\160\145\x22\40\50\160\162\151\x76\x61\x74\x65\57\160\165\142\x6c\151\143\x29\x20\155\x75\163\x74\40\142\x65\40\x70\x61\163\x73\145\144\x20\166\x69\141\40\160\141\162\x61\155\x65\x74\145\162\x73");
            case self::RSA_OAEP:
                $this->cryptParams["\154\151\x62\x72\x61\x72\x79"] = "\x6f\x70\145\x6e\x73\163\154";
                $this->cryptParams["\x70\x61\144\144\151\x6e\147"] = OPENSSL_PKCS1_OAEP_PADDING;
                $this->cryptParams["\155\145\164\x68\157\x64"] = "\150\x74\x74\x70\72\57\x2f\167\167\x77\x2e\167\x33\x2e\157\x72\147\x2f\x32\x30\x30\71\57\x78\155\x6c\145\156\x63\x31\61\x23\x72\x73\x61\x2d\157\141\x65\160";
                $this->cryptParams["\150\x61\163\150"] = "\150\x74\164\160\x3a\x2f\57\167\x77\167\x2e\x77\63\x2e\157\162\147\x2f\x32\x30\60\x39\57\170\x6d\154\x65\x6e\143\61\61\43\155\147\146\61\x73\150\x61\61";
                if (!(is_array($uF) && !empty($uF["\164\171\160\145"]))) {
                    goto WB;
                }
                if (!($uF["\164\171\160\x65"] == "\160\x75\142\x6c\x69\143" || $uF["\164\x79\x70\145"] == "\160\162\151\166\x61\164\x65")) {
                    goto LF;
                }
                $this->cryptParams["\164\x79\160\145"] = $uF["\164\171\160\x65"];
                goto bR;
                LF:
                WB:
                throw new Exception("\103\145\162\x74\151\146\x69\143\x61\x74\x65\x20\42\164\x79\x70\145\42\40\x28\160\x72\x69\x76\141\164\x65\x2f\160\x75\142\154\151\143\51\40\155\165\163\164\40\142\x65\40\160\141\163\163\x65\x64\40\166\151\141\40\160\141\162\141\x6d\x65\164\145\x72\163");
            case self::RSA_SHA1:
                $this->cryptParams["\154\151\x62\x72\x61\162\171"] = "\157\160\x65\x6e\x73\163\154";
                $this->cryptParams["\x6d\x65\x74\x68\157\x64"] = "\150\x74\x74\160\72\57\57\167\167\x77\56\167\x33\56\157\162\147\57\62\x30\60\60\x2f\60\71\57\170\x6d\154\x64\x73\151\x67\43\162\163\141\x2d\x73\150\141\x31";
                $this->cryptParams["\x70\141\144\144\151\x6e\147"] = OPENSSL_PKCS1_PADDING;
                if (!(is_array($uF) && !empty($uF["\x74\x79\x70\x65"]))) {
                    goto ya;
                }
                if (!($uF["\x74\171\160\x65"] == "\160\165\142\x6c\151\143" || $uF["\164\x79\x70\145"] == "\x70\x72\151\x76\141\164\x65")) {
                    goto z0;
                }
                $this->cryptParams["\x74\171\160\x65"] = $uF["\x74\x79\x70\145"];
                goto bR;
                z0:
                ya:
                throw new Exception("\103\x65\162\x74\151\146\151\x63\x61\x74\x65\x20\42\x74\x79\160\x65\42\x20\x28\x70\x72\x69\x76\141\164\145\57\x70\165\142\154\151\143\x29\x20\x6d\x75\163\x74\x20\x62\145\x20\160\141\x73\x73\x65\x64\40\166\x69\x61\40\x70\x61\x72\141\155\145\x74\145\x72\x73");
            case self::RSA_SHA256:
                $this->cryptParams["\154\x69\x62\x72\x61\162\x79"] = "\x6f\160\x65\x6e\163\163\154";
                $this->cryptParams["\x6d\x65\x74\150\x6f\x64"] = "\150\x74\x74\x70\72\x2f\57\167\x77\x77\x2e\167\x33\x2e\157\x72\147\57\62\x30\x30\61\x2f\x30\64\x2f\x78\155\154\x64\163\x69\147\x2d\155\x6f\162\x65\x23\162\x73\141\x2d\163\x68\141\62\x35\x36";
                $this->cryptParams["\160\x61\144\x64\151\156\147"] = OPENSSL_PKCS1_PADDING;
                $this->cryptParams["\144\151\x67\145\163\x74"] = "\x53\110\x41\62\x35\x36";
                if (!(is_array($uF) && !empty($uF["\164\x79\x70\145"]))) {
                    goto aI;
                }
                if (!($uF["\164\171\160\145"] == "\x70\x75\x62\154\151\x63" || $uF["\x74\x79\160\x65"] == "\160\x72\x69\x76\141\164\x65")) {
                    goto E3;
                }
                $this->cryptParams["\164\x79\160\145"] = $uF["\164\171\160\x65"];
                goto bR;
                E3:
                aI:
                throw new Exception("\x43\145\162\164\151\146\151\143\x61\164\x65\x20\42\164\171\160\145\42\40\x28\x70\x72\x69\x76\141\164\x65\x2f\160\x75\142\x6c\x69\x63\51\40\155\x75\163\164\40\142\145\x20\160\x61\163\163\145\144\40\x76\151\x61\40\160\x61\162\x61\155\145\x74\x65\162\163");
            case self::RSA_SHA384:
                $this->cryptParams["\154\x69\x62\162\141\162\x79"] = "\157\x70\x65\156\x73\x73\x6c";
                $this->cryptParams["\x6d\x65\x74\x68\157\144"] = "\x68\164\164\x70\x3a\57\57\x77\x77\x77\x2e\167\63\56\x6f\x72\x67\x2f\62\x30\60\x31\57\60\64\x2f\x78\x6d\x6c\144\163\x69\147\55\155\157\x72\x65\x23\x72\163\141\x2d\x73\150\141\x33\70\64";
                $this->cryptParams["\x70\141\144\x64\151\156\147"] = OPENSSL_PKCS1_PADDING;
                $this->cryptParams["\144\151\147\x65\163\164"] = "\123\110\x41\x33\x38\x34";
                if (!(is_array($uF) && !empty($uF["\164\171\x70\145"]))) {
                    goto gM;
                }
                if (!($uF["\x74\x79\x70\145"] == "\160\x75\142\x6c\x69\x63" || $uF["\x74\x79\x70\145"] == "\x70\x72\x69\166\141\x74\x65")) {
                    goto Zm;
                }
                $this->cryptParams["\164\171\x70\x65"] = $uF["\x74\171\x70\x65"];
                goto bR;
                Zm:
                gM:
                throw new Exception("\x43\145\x72\164\151\x66\151\x63\x61\x74\145\40\x22\164\x79\160\145\x22\40\50\160\x72\x69\166\141\x74\145\x2f\x70\x75\142\x6c\x69\x63\51\40\155\x75\163\164\40\x62\x65\40\160\x61\163\x73\145\x64\x20\x76\x69\141\40\x70\141\x72\x61\x6d\145\164\x65\x72\163");
            case self::RSA_SHA512:
                $this->cryptParams["\154\x69\x62\162\141\x72\x79"] = "\157\x70\145\x6e\163\x73\x6c";
                $this->cryptParams["\x6d\145\x74\150\x6f\x64"] = "\150\164\x74\160\x3a\x2f\x2f\167\x77\167\x2e\x77\x33\x2e\x6f\162\147\57\62\x30\x30\x31\x2f\x30\x34\x2f\170\155\x6c\144\163\151\147\55\155\x6f\x72\145\43\x72\163\141\x2d\x73\x68\141\x35\x31\62";
                $this->cryptParams["\x70\141\144\144\151\156\147"] = OPENSSL_PKCS1_PADDING;
                $this->cryptParams["\x64\x69\x67\x65\163\164"] = "\x53\110\x41\65\61\x32";
                if (!(is_array($uF) && !empty($uF["\x74\171\160\x65"]))) {
                    goto HX;
                }
                if (!($uF["\164\171\x70\x65"] == "\x70\165\x62\154\x69\143" || $uF["\164\x79\160\x65"] == "\x70\x72\x69\166\141\164\145")) {
                    goto Sj;
                }
                $this->cryptParams["\x74\x79\x70\145"] = $uF["\x74\x79\x70\x65"];
                goto bR;
                Sj:
                HX:
                throw new Exception("\x43\x65\162\x74\x69\146\151\x63\141\x74\145\40\x22\164\x79\x70\145\42\x20\x28\160\x72\151\166\x61\x74\x65\57\x70\165\x62\154\151\x63\x29\40\x6d\x75\163\x74\x20\x62\145\x20\x70\x61\163\x73\x65\x64\x20\166\x69\x61\40\160\x61\162\x61\155\x65\x74\x65\162\163");
            case self::HMAC_SHA1:
                $this->cryptParams["\154\151\142\162\141\x72\171"] = $O_;
                $this->cryptParams["\155\145\x74\150\x6f\144"] = "\x68\164\x74\x70\x3a\57\x2f\x77\167\167\56\167\63\x2e\157\x72\x67\x2f\x32\60\x30\60\x2f\x30\x39\57\170\x6d\154\x64\x73\151\147\43\150\x6d\141\143\x2d\x73\x68\141\x31";
                goto bR;
            default:
                throw new Exception("\x49\156\x76\141\x6c\x69\x64\40\x4b\x65\171\40\x54\171\x70\x65");
        }
        RF:
        bR:
        $this->type = $O_;
    }
    public function getSymmetricKeySize()
    {
        if (isset($this->cryptParams["\153\x65\171\x73\x69\172\145"])) {
            goto JP;
        }
        return null;
        JP:
        return $this->cryptParams["\153\145\171\163\x69\x7a\145"];
    }
    public function generateSessionKey()
    {
        if (isset($this->cryptParams["\153\x65\x79\163\x69\172\x65"])) {
            goto TT;
        }
        throw new Exception("\x55\x6e\x6b\x6e\157\x77\156\x20\x6b\145\171\40\x73\x69\172\145\40\146\157\162\40\x74\x79\x70\x65\x20\x22" . $this->type . "\x22\56");
        TT:
        $rX = $this->cryptParams["\x6b\x65\x79\x73\x69\172\x65"];
        $yQ = openssl_random_pseudo_bytes($rX);
        if (!($this->type === self::TRIPLEDES_CBC)) {
            goto Iz;
        }
        $vk = 0;
        Tj:
        if (!($vk < strlen($yQ))) {
            goto YW;
        }
        $Gz = ord($yQ[$vk]) & 0xfe;
        $fA = 1;
        $SJ = 1;
        TS:
        if (!($SJ < 8)) {
            goto xB;
        }
        $fA ^= $Gz >> $SJ & 1;
        fK:
        $SJ++;
        goto TS;
        xB:
        $Gz |= $fA;
        $yQ[$vk] = chr($Gz);
        pH:
        $vk++;
        goto Tj;
        YW:
        Iz:
        $this->key = $yQ;
        return $yQ;
    }
    public static function getRawThumbprint($N_)
    {
        $cQ = explode("\12", $N_);
        $F9 = '';
        $f_ = false;
        foreach ($cQ as $i7) {
            if (!$f_) {
                goto Zf;
            }
            if (!(strncmp($i7, "\x2d\55\x2d\55\x2d\x45\x4e\x44\40\x43\x45\x52\124\111\x46\x49\x43\x41\124\105", 20) == 0)) {
                goto Mf;
            }
            goto HY;
            Mf:
            $F9 .= trim($i7);
            goto T1;
            Zf:
            if (!(strncmp($i7, "\x2d\x2d\55\x2d\x2d\x42\x45\107\x49\x4e\x20\x43\105\x52\x54\x49\106\x49\103\x41\x54\105", 22) == 0)) {
                goto Yf;
            }
            $f_ = true;
            Yf:
            T1:
            kx:
        }
        HY:
        if (empty($F9)) {
            goto Uz;
        }
        return strtolower(sha1(base64_decode($F9)));
        Uz:
        return null;
    }
    public function loadKey($yQ, $IF = false, $qy = false)
    {
        if ($IF) {
            goto wr;
        }
        $this->key = $yQ;
        goto US;
        wr:
        $this->key = file_get_contents($yQ);
        US:
        if ($qy) {
            goto RN;
        }
        $this->x509Certificate = null;
        goto MC;
        RN:
        $this->key = openssl_x509_read($this->key);
        openssl_x509_export($this->key, $tI);
        $this->x509Certificate = $tI;
        $this->key = $tI;
        MC:
        if (!($this->cryptParams["\x6c\x69\x62\x72\x61\x72\171"] == "\157\160\x65\x6e\163\163\x6c")) {
            goto bT;
        }
        switch ($this->cryptParams["\x74\x79\160\x65"]) {
            case "\x70\165\142\x6c\151\143":
                if (!$qy) {
                    goto cK;
                }
                $this->X509Thumbprint = self::getRawThumbprint($this->key);
                cK:
                $this->key = openssl_get_publickey($this->key);
                if ($this->key) {
                    goto uD;
                }
                throw new Exception("\125\156\141\x62\154\145\x20\x74\x6f\x20\145\x78\164\162\141\143\164\x20\160\x75\x62\x6c\x69\x63\40\x6b\145\171");
                uD:
                goto FT;
            case "\160\x72\151\x76\x61\x74\145":
                $this->key = openssl_get_privatekey($this->key, $this->passphrase);
                goto FT;
            case "\x73\171\155\155\x65\x74\x72\x69\143":
                if (!(strlen($this->key) < $this->cryptParams["\x6b\145\171\x73\151\x7a\x65"])) {
                    goto di;
                }
                throw new Exception("\x4b\145\x79\40\155\x75\x73\x74\40\x63\157\156\164\x61\x69\x6e\x20\x61\x74\40\x6c\x65\x61\x73\x74\40" . $this->cryptParams["\153\x65\171\x73\151\172\x65"] . "\x20\143\x68\x61\x72\141\x63\x74\x65\162\163\40\x66\x6f\162\40\164\150\151\163\x20\x63\x69\x70\150\x65\162\54\40\143\157\x6e\x74\141\x69\156\x73\x20" . strlen($this->key));
                di:
                goto FT;
            default:
                throw new Exception("\x55\x6e\x6b\x6e\x6f\x77\156\40\164\x79\160\x65");
        }
        j_:
        FT:
        bT:
    }
    private function padISO10126($F9, $Xc)
    {
        if (!($Xc > 256)) {
            goto Pq;
        }
        throw new Exception("\102\x6c\157\x63\153\x20\x73\x69\x7a\x65\x20\150\x69\147\x68\x65\162\x20\164\150\141\x6e\40\62\65\x36\40\156\157\x74\x20\141\x6c\154\157\x77\x65\144");
        Pq:
        $IW = $Xc - strlen($F9) % $Xc;
        $KM = chr($IW);
        return $F9 . str_repeat($KM, $IW);
    }
    private function unpadISO10126($F9)
    {
        $IW = substr($F9, -1);
        $hX = ord($IW);
        return substr($F9, 0, -$hX);
    }
    private function encryptSymmetric($F9)
    {
        $this->iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length($this->cryptParams["\x63\x69\x70\150\x65\162"]));
        $jv = null;
        if (in_array($this->cryptParams["\143\x69\x70\150\x65\162"], ["\x61\x65\163\55\x31\x32\70\55\x67\143\155", "\141\x65\163\x2d\61\x39\x32\x2d\x67\x63\x6d", "\141\x65\163\x2d\62\x35\x36\x2d\147\143\x6d"])) {
            goto Q0;
        }
        $F9 = $this->padISO10126($F9, $this->cryptParams["\142\x6c\x6f\x63\x6b\163\151\172\x65"]);
        $sb = openssl_encrypt($F9, $this->cryptParams["\x63\x69\160\x68\145\162"], $this->key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $this->iv);
        goto zs;
        Q0:
        if (!(version_compare(PHP_VERSION, "\67\x2e\61\x2e\x30") < 0)) {
            goto sY;
        }
        throw new Exception("\x50\x48\120\40\67\x2e\x31\56\x30\40\151\163\x20\162\x65\x71\x75\x69\x72\x65\144\x20\164\157\x20\165\163\x65\x20\x41\x45\x53\x20\107\x43\115\x20\141\154\x67\157\x72\x69\164\150\x6d\163");
        sY:
        $jv = openssl_random_pseudo_bytes(self::AUTHTAG_LENGTH);
        $sb = openssl_encrypt($F9, $this->cryptParams["\x63\x69\x70\150\145\x72"], $this->key, OPENSSL_RAW_DATA, $this->iv, $jv);
        zs:
        if (!(false === $sb)) {
            goto U5;
        }
        throw new Exception("\106\141\x69\x6c\x75\x72\145\40\x65\x6e\143\162\x79\x70\164\151\156\147\x20\x44\141\164\x61\x20\x28\x6f\160\x65\x6e\163\163\x6c\40\163\x79\x6d\x6d\145\x74\x72\151\x63\x29\40\55\40" . openssl_error_string());
        U5:
        return $this->iv . $sb . $jv;
    }
    private function decryptSymmetric($F9)
    {
        $VR = openssl_cipher_iv_length($this->cryptParams["\x63\151\160\150\145\162"]);
        $this->iv = substr($F9, 0, $VR);
        $F9 = substr($F9, $VR);
        $jv = null;
        if (in_array($this->cryptParams["\143\151\160\150\145\x72"], ["\x61\x65\x73\x2d\x31\x32\70\55\147\143\x6d", "\x61\x65\163\55\x31\x39\x32\55\147\143\x6d", "\x61\145\x73\55\x32\65\x36\x2d\147\143\155"])) {
            goto we;
        }
        $qE = openssl_decrypt($F9, $this->cryptParams["\x63\x69\x70\150\x65\162"], $this->key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $this->iv);
        goto T0;
        we:
        if (!(version_compare(PHP_VERSION, "\67\56\x31\56\60") < 0)) {
            goto L2;
        }
        throw new Exception("\120\110\120\x20\x37\56\x31\56\x30\40\151\163\x20\x72\x65\161\x75\151\x72\145\144\x20\x74\x6f\x20\165\163\145\x20\101\x45\123\40\x47\103\x4d\40\141\154\147\x6f\x72\x69\164\x68\x6d\x73");
        L2:
        $oZ = 0 - self::AUTHTAG_LENGTH;
        $jv = substr($F9, $oZ);
        $F9 = substr($F9, 0, $oZ);
        $qE = openssl_decrypt($F9, $this->cryptParams["\143\151\160\x68\145\x72"], $this->key, OPENSSL_RAW_DATA, $this->iv, $jv);
        T0:
        if (!(false === $qE)) {
            goto Ms;
        }
        throw new Exception("\x46\x61\x69\154\x75\x72\x65\40\x64\145\x63\162\171\160\164\x69\x6e\147\40\104\141\x74\x61\x20\x28\157\160\145\156\163\x73\x6c\x20\x73\171\x6d\155\x65\x74\162\x69\143\x29\x20\x2d\x20" . openssl_error_string());
        Ms:
        return null !== $jv ? $qE : $this->unpadISO10126($qE);
    }
    private function encryptPublic($F9)
    {
        if (openssl_public_encrypt($F9, $sb, $this->key, $this->cryptParams["\160\141\144\144\151\x6e\x67"])) {
            goto rk;
        }
        throw new Exception("\106\x61\x69\x6c\x75\x72\145\x20\x65\156\143\162\x79\x70\x74\x69\156\x67\x20\104\141\x74\x61\x20\x28\x6f\160\145\156\x73\x73\x6c\40\160\165\x62\x6c\151\x63\51\x20\x2d\40" . openssl_error_string());
        rk:
        return $sb;
    }
    private function decryptPublic($F9)
    {
        if (openssl_public_decrypt($F9, $qE, $this->key, $this->cryptParams["\x70\141\144\144\x69\x6e\147"])) {
            goto CC;
        }
        throw new Exception("\x46\141\x69\154\165\x72\145\x20\144\x65\x63\x72\171\160\x74\x69\x6e\x67\40\104\x61\x74\x61\x20\x28\x6f\160\145\x6e\x73\163\x6c\40\x70\x75\142\x6c\151\143\51\x20\x2d\40" . openssl_error_string());
        CC:
        return $qE;
    }
    private function encryptPrivate($F9)
    {
        if (openssl_private_encrypt($F9, $sb, $this->key, $this->cryptParams["\160\x61\144\144\151\156\x67"])) {
            goto Il;
        }
        throw new Exception("\106\141\x69\154\x75\162\x65\x20\x65\x6e\143\162\x79\x70\164\151\156\147\40\x44\x61\x74\x61\x20\x28\157\x70\145\156\163\x73\154\40\160\x72\x69\x76\141\x74\145\x29\40\55\x20" . openssl_error_string());
        Il:
        return $sb;
    }
    private function decryptPrivate($F9)
    {
        if (openssl_private_decrypt($F9, $qE, $this->key, $this->cryptParams["\160\x61\x64\144\x69\156\x67"])) {
            goto Cj;
        }
        throw new Exception("\106\x61\x69\x6c\x75\162\145\x20\144\x65\x63\x72\x79\x70\164\x69\156\x67\40\104\x61\x74\141\40\50\157\160\x65\156\163\163\154\x20\x70\x72\151\166\x61\x74\145\x29\40\x2d\x20" . openssl_error_string());
        Cj:
        return $qE;
    }
    private function signOpenSSL($F9)
    {
        $GC = OPENSSL_ALGO_SHA1;
        if (empty($this->cryptParams["\144\151\x67\x65\163\x74"])) {
            goto UF;
        }
        $GC = $this->cryptParams["\x64\151\147\145\163\164"];
        UF:
        if (openssl_sign($F9, $Qz, $this->key, $GC)) {
            goto uU;
        }
        throw new Exception("\106\x61\151\x6c\x75\x72\145\40\123\151\147\x6e\151\156\x67\x20\x44\x61\x74\141\x3a\x20" . openssl_error_string() . "\40\55\x20" . $GC);
        uU:
        return $Qz;
    }
    private function verifyOpenSSL($F9, $Qz)
    {
        $GC = OPENSSL_ALGO_SHA1;
        if (empty($this->cryptParams["\x64\151\x67\x65\x73\164"])) {
            goto CK;
        }
        $GC = $this->cryptParams["\144\151\147\x65\x73\x74"];
        CK:
        return openssl_verify($F9, $Qz, $this->key, $GC);
    }
    public function encryptData($F9)
    {
        if (!($this->cryptParams["\x6c\151\142\x72\x61\162\x79"] === "\x6f\160\145\x6e\163\x73\154")) {
            goto Iy;
        }
        switch ($this->cryptParams["\x74\x79\x70\x65"]) {
            case "\x73\171\x6d\155\145\164\x72\151\143":
                return $this->encryptSymmetric($F9);
            case "\x70\165\x62\154\151\x63":
                return $this->encryptPublic($F9);
            case "\x70\x72\x69\x76\141\164\x65":
                return $this->encryptPrivate($F9);
        }
        cc:
        H8:
        Iy:
    }
    public function decryptData($F9)
    {
        if (!($this->cryptParams["\x6c\151\142\x72\141\162\x79"] === "\x6f\160\145\156\x73\163\x6c")) {
            goto qX;
        }
        switch ($this->cryptParams["\164\171\160\x65"]) {
            case "\x73\x79\155\155\x65\x74\162\151\143":
                return $this->decryptSymmetric($F9);
            case "\160\165\x62\x6c\x69\143":
                return $this->decryptPublic($F9);
            case "\160\x72\151\x76\141\164\x65":
                return $this->decryptPrivate($F9);
        }
        c3:
        w3:
        qX:
    }
    public function signData($F9)
    {
        switch ($this->cryptParams["\154\151\142\x72\x61\x72\171"]) {
            case "\x6f\160\x65\x6e\163\x73\154":
                return $this->signOpenSSL($F9);
            case self::HMAC_SHA1:
                return hash_hmac("\163\150\x61\x31", $F9, $this->key, true);
        }
        z5:
        T3:
    }
    public function verifySignature($F9, $Qz)
    {
        switch ($this->cryptParams["\154\151\x62\x72\x61\162\171"]) {
            case "\x6f\x70\x65\x6e\163\x73\x6c":
                return $this->verifyOpenSSL($F9, $Qz);
            case self::HMAC_SHA1:
                $el = hash_hmac("\x73\150\141\x31", $F9, $this->key, true);
                return strcmp($Qz, $el) == 0;
        }
        rt:
        Uy:
    }
    public function getAlgorith()
    {
        return $this->getAlgorithm();
    }
    public function getAlgorithm()
    {
        return $this->cryptParams["\x6d\145\x74\150\x6f\x64"];
    }
    public static function makeAsnSegment($O_, $L4)
    {
        switch ($O_) {
            case 0x2:
                if (!(ord($L4) > 0x7f)) {
                    goto zF;
                }
                $L4 = chr(0) . $L4;
                zF:
                goto s3;
            case 0x3:
                $L4 = chr(0) . $L4;
                goto s3;
        }
        gE:
        s3:
        $di = strlen($L4);
        if ($di < 128) {
            goto KF;
        }
        if ($di < 0x100) {
            goto Dy;
        }
        if ($di < 0x10000) {
            goto Fy;
        }
        $GZ = null;
        goto Tu;
        Fy:
        $GZ = sprintf("\x25\x63\45\x63\x25\143\45\x63\x25\x73", $O_, 0x82, $di / 0x100, $di % 0x100, $L4);
        Tu:
        goto oJ;
        Dy:
        $GZ = sprintf("\x25\x63\x25\x63\45\143\45\x73", $O_, 0x81, $di, $L4);
        oJ:
        goto Ty;
        KF:
        $GZ = sprintf("\x25\x63\x25\143\x25\163", $O_, $di, $L4);
        Ty:
        return $GZ;
    }
    public static function convertRSA($G9, $i4)
    {
        $Zf = self::makeAsnSegment(0x2, $i4);
        $tr = self::makeAsnSegment(0x2, $G9);
        $rf = self::makeAsnSegment(0x30, $tr . $Zf);
        $es = self::makeAsnSegment(0x3, $rf);
        $YY = pack("\110\52", "\x33\x30\60\x44\x30\x36\x30\x39\62\101\x38\x36\64\x38\x38\x36\106\x37\60\104\60\x31\x30\61\60\x31\x30\65\x30\60");
        $hd = self::makeAsnSegment(0x30, $YY . $es);
        $Gi = base64_encode($hd);
        $vg = "\x2d\x2d\x2d\x2d\x2d\x42\x45\x47\x49\x4e\x20\x50\125\102\x4c\x49\103\40\x4b\105\131\55\x2d\55\55\55\12";
        $oZ = 0;
        ZM:
        if (!($NY = substr($Gi, $oZ, 64))) {
            goto Xf;
        }
        $vg = $vg . $NY . "\12";
        $oZ += 64;
        goto ZM;
        Xf:
        return $vg . "\x2d\x2d\x2d\55\x2d\105\x4e\104\40\120\125\x42\x4c\x49\103\x20\x4b\105\x59\x2d\55\55\55\x2d\xa";
    }
    public function serializeKey($rM)
    {
    }
    public function getX509Certificate()
    {
        return $this->x509Certificate;
    }
    public function getX509Thumbprint()
    {
        return $this->X509Thumbprint;
    }
    public static function fromEncryptedKeyElement(DOMElement $cJ)
    {
        $NF = new XMLSecEnc();
        $NF->setNode($cJ);
        if ($mx = $NF->locateKey()) {
            goto gB;
        }
        throw new Exception("\x55\156\141\142\x6c\x65\x20\164\157\40\154\x6f\x63\141\164\145\x20\141\154\147\x6f\x72\x69\x74\x68\x6d\40\x66\x6f\162\40\164\150\x69\x73\40\x45\x6e\143\x72\x79\x70\x74\145\x64\x20\113\x65\171");
        gB:
        $mx->isEncrypted = true;
        $mx->encryptedCtx = $NF;
        XMLSecEnc::staticLocateKeyInfo($mx, $cJ);
        return $mx;
    }
}
