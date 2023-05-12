<?php


namespace Drupal\miniorange_saml;

use DOMDocument;
use DOMElement;
use DOMXPath;
use Exception;
class XMLSecurityKey
{
    const TRIPLEDES_CBC = "\150\x74\x74\160\72\x2f\x2f\x77\167\x77\x2e\167\x33\56\157\x72\x67\x2f\x32\x30\60\61\x2f\60\x34\x2f\170\x6d\x6c\x65\x6e\143\43\x74\162\x69\x70\154\145\144\x65\163\x2d\x63\142\143";
    const AES128_CBC = "\x68\x74\164\x70\72\x2f\x2f\x77\167\167\x2e\167\x33\x2e\157\162\x67\57\62\x30\60\61\57\60\64\x2f\x78\155\154\x65\x6e\143\x23\141\x65\163\61\62\70\55\x63\x62\143";
    const AES192_CBC = "\150\x74\x74\x70\x3a\57\x2f\167\x77\x77\x2e\x77\x33\56\157\162\147\x2f\x32\x30\x30\61\x2f\x30\x34\x2f\170\x6d\154\145\x6e\143\x23\x61\x65\x73\x31\x39\62\55\143\142\x63";
    const AES256_CBC = "\x68\164\164\160\72\x2f\57\x77\x77\x77\56\x77\x33\x2e\x6f\x72\x67\57\62\60\60\61\x2f\x30\64\x2f\170\x6d\x6c\145\x6e\143\43\x61\145\163\62\65\66\55\x63\142\143";
    const RSA_1_5 = "\150\164\x74\x70\72\x2f\x2f\167\x77\167\x2e\167\x33\56\157\162\x67\57\x32\60\60\61\x2f\60\x34\x2f\170\155\154\145\x6e\143\43\162\x73\141\55\x31\x5f\x35";
    const RSA_OAEP_MGF1P = "\x68\164\164\160\72\x2f\57\167\167\x77\x2e\167\63\56\157\162\x67\x2f\x32\60\60\61\57\60\x34\57\170\155\154\145\x6e\143\43\x72\163\x61\x2d\x6f\141\145\160\55\x6d\x67\x66\61\160";
    const DSA_SHA1 = "\x68\x74\x74\160\72\57\57\x77\x77\x77\x2e\x77\63\56\x6f\x72\x67\x2f\x32\60\x30\60\x2f\60\71\57\170\155\154\144\163\x69\147\x23\144\163\141\55\x73\x68\141\61";
    const RSA_SHA1 = "\150\164\x74\x70\x3a\x2f\57\167\x77\x77\x2e\x77\x33\x2e\157\x72\x67\57\62\60\x30\x30\57\60\71\57\x78\x6d\x6c\x64\x73\151\147\43\x72\163\141\x2d\x73\x68\141\61";
    const RSA_SHA256 = "\x68\x74\x74\x70\x3a\57\57\x77\167\x77\x2e\167\63\56\x6f\x72\147\57\x32\x30\60\61\57\x30\x34\x2f\170\x6d\x6c\144\163\x69\x67\x2d\155\x6f\x72\x65\43\162\163\141\55\163\150\x61\x32\65\x36";
    const RSA_SHA384 = "\x68\164\x74\160\72\57\x2f\167\x77\x77\x2e\x77\63\56\x6f\x72\x67\57\x32\60\x30\x31\57\60\x34\57\x78\x6d\x6c\x64\x73\x69\147\x2d\x6d\157\162\x65\43\x72\x73\x61\55\163\150\141\x33\x38\64";
    const RSA_SHA512 = "\x68\x74\x74\160\72\57\x2f\167\x77\x77\x2e\x77\x33\x2e\x6f\x72\147\57\62\x30\x30\x31\57\x30\64\x2f\170\x6d\x6c\144\x73\x69\147\55\x6d\157\x72\x65\43\162\x73\141\55\x73\150\x61\x35\x31\x32";
    const HMAC_SHA1 = "\150\164\164\160\x3a\57\57\x77\x77\x77\x2e\167\x33\56\x6f\x72\147\57\62\60\60\60\x2f\60\71\x2f\170\x6d\154\x64\x73\151\x67\43\x68\x6d\141\143\55\x73\x68\x61\61";
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
    public function __construct($Hm, $Yk = null)
    {
        switch ($Hm) {
            case self::TRIPLEDES_CBC:
                $this->cryptParams["\x6c\151\x62\x72\x61\162\171"] = "\x6f\x70\145\156\163\163\x6c";
                $this->cryptParams["\143\x69\x70\x68\x65\x72"] = "\x64\145\x73\x2d\145\144\x65\63\x2d\x63\x62\x63";
                $this->cryptParams["\164\x79\160\x65"] = "\x73\171\x6d\x6d\145\x74\162\x69\x63";
                $this->cryptParams["\x6d\145\164\150\157\144"] = "\x68\x74\164\160\x3a\57\x2f\167\x77\167\56\x77\63\56\157\162\x67\x2f\x32\60\x30\x31\x2f\60\x34\57\x78\x6d\x6c\145\156\143\x23\164\162\x69\x70\154\145\x64\x65\x73\x2d\x63\142\143";
                $this->cryptParams["\x6b\x65\x79\x73\151\x7a\x65"] = 24;
                $this->cryptParams["\x62\x6c\157\x63\x6b\163\151\172\x65"] = 8;
                goto KB;
            case self::AES128_CBC:
                $this->cryptParams["\154\151\142\x72\x61\x72\x79"] = "\157\x70\x65\x6e\x73\163\154";
                $this->cryptParams["\x63\x69\160\x68\145\x72"] = "\x61\145\x73\55\61\x32\x38\55\x63\142\x63";
                $this->cryptParams["\x74\x79\160\145"] = "\163\171\155\x6d\145\x74\x72\x69\143";
                $this->cryptParams["\x6d\x65\164\150\157\144"] = "\x68\164\x74\160\72\57\x2f\167\167\167\x2e\x77\63\56\157\x72\147\x2f\x32\60\x30\x31\x2f\60\64\x2f\170\x6d\x6c\145\x6e\x63\x23\x61\145\163\x31\62\x38\x2d\x63\142\x63";
                $this->cryptParams["\153\x65\171\163\151\x7a\145"] = 16;
                $this->cryptParams["\x62\154\157\x63\153\163\x69\172\145"] = 16;
                goto KB;
            case self::AES192_CBC:
                $this->cryptParams["\154\151\142\x72\x61\x72\x79"] = "\x6f\x70\145\x6e\x73\163\x6c";
                $this->cryptParams["\143\151\160\150\145\162"] = "\x61\145\x73\55\x31\71\x32\x2d\x63\x62\143";
                $this->cryptParams["\x74\171\160\145"] = "\163\171\x6d\155\x65\164\162\151\x63";
                $this->cryptParams["\x6d\145\164\150\157\144"] = "\150\x74\x74\x70\72\x2f\57\x77\x77\167\56\167\63\x2e\x6f\162\x67\x2f\x32\60\60\x31\x2f\60\x34\57\170\155\154\145\156\x63\43\141\145\x73\61\x39\x32\x2d\143\142\143";
                $this->cryptParams["\153\145\171\x73\x69\172\145"] = 24;
                $this->cryptParams["\142\x6c\157\x63\x6b\163\x69\x7a\145"] = 16;
                goto KB;
            case self::AES256_CBC:
                $this->cryptParams["\x6c\x69\x62\x72\x61\162\x79"] = "\157\x70\145\x6e\163\163\154";
                $this->cryptParams["\x63\151\x70\150\145\162"] = "\141\x65\163\x2d\62\65\x36\55\x63\142\143";
                $this->cryptParams["\164\x79\x70\x65"] = "\163\x79\155\x6d\x65\164\x72\151\x63";
                $this->cryptParams["\155\x65\x74\150\157\x64"] = "\x68\164\x74\160\x3a\x2f\57\167\x77\167\x2e\167\x33\x2e\x6f\162\147\x2f\x32\x30\x30\61\57\x30\64\57\x78\155\x6c\x65\156\x63\43\x61\x65\163\62\x35\66\55\143\x62\x63";
                $this->cryptParams["\x6b\145\x79\163\151\x7a\145"] = 32;
                $this->cryptParams["\x62\x6c\x6f\143\x6b\x73\151\172\145"] = 16;
                goto KB;
            case self::RSA_1_5:
                $this->cryptParams["\x6c\151\x62\x72\141\162\171"] = "\x6f\160\x65\x6e\163\x73\154";
                $this->cryptParams["\x70\141\144\x64\151\x6e\147"] = OPENSSL_PKCS1_PADDING;
                $this->cryptParams["\x6d\145\x74\x68\x6f\x64"] = "\150\x74\x74\x70\x3a\57\x2f\x77\x77\167\56\x77\63\56\x6f\162\147\x2f\62\x30\x30\x31\x2f\60\64\57\x78\155\x6c\x65\x6e\143\x23\162\x73\x61\x2d\61\137\65";
                if (!(is_array($Yk) && !empty($Yk["\x74\171\x70\145"]))) {
                    goto Ve;
                }
                if (!($Yk["\164\x79\160\x65"] == "\160\165\x62\x6c\x69\143" || $Yk["\164\171\x70\145"] == "\x70\x72\151\166\141\x74\x65")) {
                    goto jU;
                }
                $this->cryptParams["\164\x79\x70\145"] = $Yk["\164\171\x70\x65"];
                goto KB;
                jU:
                Ve:
                throw new Exception("\103\x65\162\164\151\x66\x69\143\x61\164\145\x20\42\x74\x79\x70\x65\x22\40\50\160\162\151\x76\x61\x74\x65\x2f\x70\x75\x62\x6c\151\143\51\40\x6d\165\x73\164\40\x62\x65\40\x70\x61\163\x73\x65\144\40\x76\x69\x61\40\x70\x61\x72\141\155\x65\164\145\162\x73");
            case self::RSA_OAEP_MGF1P:
                $this->cryptParams["\154\151\142\162\x61\x72\x79"] = "\157\x70\x65\x6e\163\x73\154";
                $this->cryptParams["\x70\141\144\144\151\x6e\x67"] = OPENSSL_PKCS1_OAEP_PADDING;
                $this->cryptParams["\x6d\145\x74\150\x6f\x64"] = "\150\164\164\x70\x3a\x2f\x2f\x77\x77\167\x2e\167\x33\56\157\x72\147\x2f\62\60\60\x31\57\60\64\x2f\x78\x6d\154\145\156\143\x23\x72\x73\141\55\157\141\145\160\x2d\x6d\x67\x66\x31\x70";
                $this->cryptParams["\150\141\163\150"] = null;
                if (!(is_array($Yk) && !empty($Yk["\x74\171\x70\145"]))) {
                    goto C3;
                }
                if (!($Yk["\x74\x79\160\x65"] == "\160\165\142\154\151\143" || $Yk["\x74\x79\x70\145"] == "\x70\x72\151\166\141\164\145")) {
                    goto lJ;
                }
                $this->cryptParams["\164\171\160\x65"] = $Yk["\164\x79\160\x65"];
                goto KB;
                lJ:
                C3:
                throw new Exception("\x43\145\x72\164\151\x66\x69\x63\141\164\145\40\42\x74\171\160\145\42\x20\50\160\162\x69\166\141\164\145\x2f\160\x75\142\154\x69\143\51\40\x6d\165\163\164\40\142\145\40\x70\x61\163\x73\145\x64\x20\x76\x69\141\40\x70\141\x72\141\x6d\x65\164\145\x72\163");
            case self::RSA_SHA1:
                $this->cryptParams["\154\x69\142\162\141\x72\x79"] = "\x6f\160\145\156\x73\x73\x6c";
                $this->cryptParams["\x6d\x65\x74\150\x6f\144"] = "\x68\x74\164\x70\72\x2f\x2f\x77\x77\x77\56\x77\x33\56\x6f\x72\x67\x2f\62\x30\60\60\x2f\60\x39\x2f\170\155\154\x64\x73\x69\x67\x23\x72\x73\x61\55\163\150\x61\61";
                $this->cryptParams["\160\x61\144\144\151\156\x67"] = OPENSSL_PKCS1_PADDING;
                if (!(is_array($Yk) && !empty($Yk["\x74\x79\160\145"]))) {
                    goto Lt;
                }
                if (!($Yk["\164\171\x70\x65"] == "\160\x75\142\154\x69\x63" || $Yk["\x74\x79\x70\x65"] == "\160\x72\151\166\141\x74\x65")) {
                    goto Yv;
                }
                $this->cryptParams["\164\171\x70\x65"] = $Yk["\x74\171\x70\145"];
                goto KB;
                Yv:
                Lt:
                throw new Exception("\x43\x65\x72\x74\x69\x66\151\143\141\x74\x65\40\x22\164\171\160\145\x22\40\50\x70\162\151\166\141\164\x65\x2f\160\x75\x62\x6c\x69\143\51\x20\x6d\x75\163\164\40\142\x65\40\x70\141\163\163\x65\x64\x20\166\151\141\40\x70\x61\x72\x61\x6d\x65\x74\145\162\x73");
            case self::RSA_SHA256:
                $this->cryptParams["\x6c\x69\142\x72\141\x72\x79"] = "\x6f\x70\145\156\x73\163\x6c";
                $this->cryptParams["\x6d\x65\x74\150\157\144"] = "\150\164\x74\x70\72\x2f\57\167\167\x77\x2e\167\x33\56\x6f\162\x67\x2f\x32\x30\60\61\x2f\x30\x34\57\170\x6d\154\x64\163\151\147\55\x6d\x6f\x72\x65\x23\162\163\141\55\x73\x68\141\62\x35\x36";
                $this->cryptParams["\160\141\x64\144\x69\156\x67"] = OPENSSL_PKCS1_PADDING;
                $this->cryptParams["\x64\x69\x67\145\163\x74"] = "\x53\x48\x41\x32\65\66";
                if (!(is_array($Yk) && !empty($Yk["\x74\x79\160\145"]))) {
                    goto Hd;
                }
                if (!($Yk["\164\x79\160\145"] == "\x70\x75\x62\154\x69\x63" || $Yk["\164\171\x70\x65"] == "\x70\x72\151\166\x61\x74\x65")) {
                    goto zh;
                }
                $this->cryptParams["\x74\x79\x70\x65"] = $Yk["\x74\x79\160\145"];
                goto KB;
                zh:
                Hd:
                throw new Exception("\x43\x65\162\x74\151\x66\151\143\x61\x74\145\x20\x22\164\171\x70\x65\x22\x20\50\x70\162\x69\x76\x61\x74\x65\57\160\x75\x62\x6c\x69\x63\51\40\x6d\165\163\x74\x20\x62\x65\x20\x70\141\163\x73\x65\144\40\x76\151\141\40\x70\x61\162\x61\155\145\x74\x65\x72\163");
            case self::RSA_SHA384:
                $this->cryptParams["\x6c\151\x62\x72\141\x72\171"] = "\157\160\x65\156\163\163\x6c";
                $this->cryptParams["\x6d\145\x74\150\157\144"] = "\x68\164\x74\x70\x3a\x2f\x2f\167\x77\x77\x2e\167\63\56\x6f\162\x67\x2f\x32\60\60\x31\x2f\60\x34\57\170\x6d\x6c\144\x73\x69\147\55\x6d\157\162\x65\43\162\x73\x61\x2d\163\150\x61\x33\70\x34";
                $this->cryptParams["\x70\x61\x64\x64\151\x6e\x67"] = OPENSSL_PKCS1_PADDING;
                $this->cryptParams["\144\151\147\x65\x73\164"] = "\123\110\x41\x33\70\x34";
                if (!(is_array($Yk) && !empty($Yk["\x74\x79\160\x65"]))) {
                    goto Qp;
                }
                if (!($Yk["\164\x79\160\x65"] == "\160\x75\142\154\151\143" || $Yk["\x74\171\x70\x65"] == "\x70\x72\151\166\x61\164\145")) {
                    goto AB;
                }
                $this->cryptParams["\164\171\x70\145"] = $Yk["\x74\171\x70\x65"];
                goto KB;
                AB:
                Qp:
                throw new Exception("\x43\145\x72\164\151\x66\151\x63\x61\164\145\40\42\164\171\x70\145\x22\x20\50\160\x72\x69\x76\141\x74\145\x2f\x70\165\x62\154\151\143\x29\x20\155\165\163\164\x20\142\x65\x20\x70\141\163\x73\x65\x64\40\x76\151\x61\40\x70\x61\162\141\155\145\164\145\x72\x73");
            case self::RSA_SHA512:
                $this->cryptParams["\154\x69\142\162\141\162\171"] = "\x6f\160\145\x6e\x73\163\154";
                $this->cryptParams["\155\x65\x74\x68\x6f\x64"] = "\150\164\164\160\x3a\57\x2f\x77\x77\167\x2e\167\63\56\x6f\162\147\57\x32\60\60\61\57\x30\64\x2f\x78\x6d\154\x64\x73\x69\147\x2d\x6d\157\162\x65\43\x72\163\x61\x2d\163\x68\141\x35\61\62";
                $this->cryptParams["\x70\x61\x64\144\x69\156\147"] = OPENSSL_PKCS1_PADDING;
                $this->cryptParams["\144\x69\147\145\x73\164"] = "\x53\110\x41\x35\x31\62";
                if (!(is_array($Yk) && !empty($Yk["\x74\x79\x70\x65"]))) {
                    goto va;
                }
                if (!($Yk["\164\171\x70\x65"] == "\160\165\x62\x6c\x69\143" || $Yk["\164\x79\160\x65"] == "\160\x72\151\x76\141\x74\145")) {
                    goto fP;
                }
                $this->cryptParams["\x74\x79\160\x65"] = $Yk["\x74\171\160\x65"];
                goto KB;
                fP:
                va:
                throw new Exception("\x43\x65\162\164\151\146\151\143\x61\x74\x65\x20\42\164\x79\x70\145\x22\x20\50\160\x72\x69\166\141\x74\x65\x2f\x70\165\x62\154\x69\x63\51\40\x6d\x75\x73\164\x20\x62\x65\x20\160\x61\x73\x73\145\x64\x20\x76\151\x61\40\x70\x61\x72\141\155\145\x74\145\x72\x73");
            case self::HMAC_SHA1:
                $this->cryptParams["\154\151\x62\162\141\162\x79"] = $Hm;
                $this->cryptParams["\x6d\x65\x74\x68\x6f\x64"] = "\x68\164\x74\160\72\57\57\x77\x77\167\56\167\x33\56\x6f\162\147\57\x32\60\60\x30\57\x30\71\x2f\170\155\x6c\x64\x73\151\147\x23\x68\155\141\x63\x2d\163\x68\141\x31";
                goto KB;
            default:
                throw new Exception("\x49\x6e\x76\x61\154\x69\x64\x20\x4b\145\171\40\x54\171\160\x65");
        }
        vk:
        KB:
        $this->type = $Hm;
    }
    public function getSymmetricKeySize()
    {
        if (isset($this->cryptParams["\x6b\x65\x79\x73\x69\x7a\145"])) {
            goto k4;
        }
        return null;
        k4:
        return $this->cryptParams["\x6b\x65\x79\x73\151\x7a\145"];
    }
    public function generateSessionKey()
    {
        if (isset($this->cryptParams["\153\x65\171\x73\x69\x7a\x65"])) {
            goto Nk;
        }
        throw new Exception("\125\x6e\153\156\157\167\x6e\40\x6b\x65\x79\40\x73\x69\172\145\x20\146\x6f\162\x20\x74\171\x70\x65\x20\x22" . $this->type . "\x22\56");
        Nk:
        $hx = $this->cryptParams["\153\145\171\163\151\x7a\145"];
        $eQ = openssl_random_pseudo_bytes($hx);
        if (!($this->type === self::TRIPLEDES_CBC)) {
            goto QM;
        }
        $mp = 0;
        Gj:
        if (!($mp < strlen($eQ))) {
            goto WJ;
        }
        $GF = ord($eQ[$mp]) & 0xfe;
        $MH = 1;
        $mo = 1;
        xo:
        if (!($mo < 8)) {
            goto ra;
        }
        $MH ^= $GF >> $mo & 1;
        hX:
        $mo++;
        goto xo;
        ra:
        $GF |= $MH;
        $eQ[$mp] = chr($GF);
        pL:
        $mp++;
        goto Gj;
        WJ:
        QM:
        $this->key = $eQ;
        return $eQ;
    }
    public static function getRawThumbprint($Jw)
    {
        $xi = explode("\xa", $Jw);
        $LF = '';
        $GU = false;
        foreach ($xi as $Jx) {
            if (!$GU) {
                goto je;
            }
            if (!(strncmp($Jx, "\x2d\x2d\55\x2d\x2d\x45\116\104\x20\x43\105\122\x54\111\106\111\x43\x41\124\105", 20) == 0)) {
                goto RK;
            }
            goto Na;
            RK:
            $LF .= trim($Jx);
            goto T2;
            je:
            if (!(strncmp($Jx, "\x2d\x2d\x2d\x2d\55\x42\x45\107\x49\x4e\x20\103\105\122\x54\111\106\x49\x43\101\x54\105", 22) == 0)) {
                goto LG;
            }
            $GU = true;
            LG:
            T2:
            nh:
        }
        Na:
        if (empty($LF)) {
            goto GN;
        }
        return strtolower(sha1(base64_decode($LF)));
        GN:
        return null;
    }
    public function loadKey($eQ, $V_ = false, $UI = false)
    {
        if ($V_) {
            goto I7;
        }
        $this->key = $eQ;
        goto w_;
        I7:
        $this->key = file_get_contents($eQ);
        w_:
        if ($UI) {
            goto l4;
        }
        $this->x509Certificate = null;
        goto Ge;
        l4:
        $this->key = openssl_x509_read($this->key);
        openssl_x509_export($this->key, $nI);
        $this->x509Certificate = $nI;
        $this->key = $nI;
        Ge:
        if (!($this->cryptParams["\x6c\151\142\162\141\x72\x79"] == "\x6f\160\x65\x6e\x73\x73\x6c")) {
            goto zb;
        }
        switch ($this->cryptParams["\164\x79\x70\x65"]) {
            case "\x70\165\142\x6c\x69\143":
                if (!$UI) {
                    goto zD;
                }
                $this->X509Thumbprint = self::getRawThumbprint($this->key);
                zD:
                $this->key = openssl_get_publickey($this->key);
                if ($this->key) {
                    goto ML;
                }
                throw new Exception("\125\x6e\141\x62\x6c\145\x20\x74\x6f\x20\x65\x78\x74\162\141\x63\164\x20\160\165\142\x6c\151\143\40\153\x65\171");
                ML:
                goto mD;
            case "\x70\x72\151\166\141\x74\145":
                $this->key = openssl_get_privatekey($this->key, $this->passphrase);
                goto mD;
            case "\163\x79\x6d\155\145\x74\162\x69\143":
                if (!(strlen($this->key) < $this->cryptParams["\153\x65\x79\x73\151\x7a\145"])) {
                    goto Qs;
                }
                throw new Exception("\113\x65\x79\x20\155\165\163\164\x20\x63\157\x6e\164\141\x69\x6e\x20\x61\164\x20\x6c\145\141\x73\164\x20\62\65\x20\x63\150\141\162\x61\143\164\x65\162\x73\40\x66\x6f\162\x20\x74\x68\x69\x73\40\143\x69\160\x68\x65\x72");
                Qs:
                goto mD;
            default:
                throw new Exception("\x55\x6e\x6b\x6e\157\x77\x6e\x20\x74\171\160\145");
        }
        WE:
        mD:
        zb:
    }
    private function padISO10126($LF, $vC)
    {
        if (!($vC > 256)) {
            goto DH;
        }
        throw new Exception("\102\x6c\157\143\x6b\x20\x73\x69\172\x65\40\150\x69\x67\x68\x65\x72\40\x74\150\141\x6e\x20\x32\65\66\40\x6e\x6f\x74\40\x61\x6c\x6c\x6f\167\145\x64");
        DH:
        $f0 = $vC - strlen($LF) % $vC;
        $Vk = chr($f0);
        return $LF . str_repeat($Vk, $f0);
    }
    private function unpadISO10126($LF)
    {
        $f0 = substr($LF, -1);
        $v3 = ord($f0);
        return substr($LF, 0, -$v3);
    }
    private function encryptSymmetric($LF)
    {
        $this->iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length($this->cryptParams["\143\151\x70\x68\145\162"]));
        $LF = $this->padISO10126($LF, $this->cryptParams["\142\x6c\x6f\143\x6b\x73\151\x7a\145"]);
        $P_ = openssl_encrypt($LF, $this->cryptParams["\x63\151\x70\150\x65\x72"], $this->key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $this->iv);
        if (!(false === $P_)) {
            goto LO;
        }
        throw new Exception("\106\x61\x69\154\165\162\x65\40\x65\156\143\x72\x79\x70\x74\151\156\147\40\104\x61\164\141\40\x28\157\x70\x65\x6e\x73\163\x6c\40\x73\x79\x6d\155\145\x74\x72\x69\143\51\x20\x2d\40" . openssl_error_string());
        LO:
        return $this->iv . $P_;
    }
    private function decryptSymmetric($LF)
    {
        $v1 = openssl_cipher_iv_length($this->cryptParams["\143\151\x70\150\145\162"]);
        $this->iv = substr($LF, 0, $v1);
        $LF = substr($LF, $v1);
        $gL = openssl_decrypt($LF, $this->cryptParams["\143\x69\x70\x68\x65\162"], $this->key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $this->iv);
        if (!(false === $gL)) {
            goto M8;
        }
        throw new Exception("\106\141\151\154\165\x72\145\x20\144\x65\x63\x72\x79\160\164\151\156\x67\40\x44\x61\x74\x61\x20\x28\157\160\145\x6e\x73\163\154\40\x73\x79\155\155\x65\164\162\151\x63\51\x20\55\x20" . openssl_error_string());
        M8:
        return $this->unpadISO10126($gL);
    }
    private function encryptPublic($LF)
    {
        if (openssl_public_encrypt($LF, $P_, $this->key, $this->cryptParams["\160\x61\144\x64\x69\156\147"])) {
            goto tD;
        }
        throw new Exception("\106\x61\151\154\165\x72\x65\40\x65\156\143\x72\x79\x70\x74\151\156\147\40\x44\x61\x74\141\x20\50\x6f\160\x65\156\163\x73\x6c\x20\160\x75\x62\x6c\151\x63\51\40\55\x20" . openssl_error_string());
        tD:
        return $P_;
    }
    private function decryptPublic($LF)
    {
        if (openssl_public_decrypt($LF, $gL, $this->key, $this->cryptParams["\160\141\x64\144\151\156\x67"])) {
            goto ya;
        }
        throw new Exception("\106\141\x69\x6c\165\x72\x65\x20\144\x65\143\162\x79\160\x74\x69\x6e\x67\40\104\x61\x74\141\x20\50\x6f\160\x65\156\163\x73\154\40\160\165\x62\x6c\151\x63\51\x20\x2d\x20" . openssl_error_string);
        ya:
        return $gL;
    }
    private function encryptPrivate($LF)
    {
        if (openssl_private_encrypt($LF, $P_, $this->key, $this->cryptParams["\160\141\144\144\151\x6e\147"])) {
            goto qF;
        }
        throw new Exception("\106\x61\151\x6c\x75\162\x65\40\x65\156\x63\x72\171\x70\x74\x69\156\147\40\104\x61\164\x61\x20\50\157\160\x65\156\163\x73\x6c\x20\160\x72\x69\166\x61\x74\x65\51\40\x2d\x20" . openssl_error_string());
        qF:
        return $P_;
    }
    private function decryptPrivate($LF)
    {
        if (openssl_private_decrypt($LF, $gL, $this->key, $this->cryptParams["\x70\x61\x64\x64\151\x6e\147"])) {
            goto xE;
        }
        throw new Exception("\106\x61\151\x6c\165\162\145\x20\144\145\x63\x72\x79\160\x74\151\x6e\x67\x20\x44\141\x74\141\40\x28\x6f\160\145\156\163\x73\154\x20\160\x72\151\166\141\164\145\x29\x20\55\x20" . openssl_error_string());
        xE:
        return $gL;
    }
    private function signOpenSSL($LF)
    {
        $yY = OPENSSL_ALGO_SHA1;
        if (empty($this->cryptParams["\144\151\147\145\x73\x74"])) {
            goto lp;
        }
        $yY = $this->cryptParams["\144\151\147\145\x73\164"];
        lp:
        if (openssl_sign($LF, $Tm, $this->key, $yY)) {
            goto Bn;
        }
        throw new Exception("\x46\x61\x69\154\x75\x72\x65\40\123\x69\x67\156\x69\156\147\x20\104\x61\164\141\72\x20" . openssl_error_string() . "\x20\x2d\40" . $yY);
        Bn:
        return $Tm;
    }
    private function verifyOpenSSL($LF, $Tm)
    {
        $yY = OPENSSL_ALGO_SHA1;
        if (empty($this->cryptParams["\x64\x69\147\145\163\x74"])) {
            goto wL;
        }
        $yY = $this->cryptParams["\144\151\x67\145\x73\164"];
        wL:
        return openssl_verify($LF, $Tm, $this->key, $yY);
    }
    public function encryptData($LF)
    {
        if (!($this->cryptParams["\x6c\x69\x62\162\141\x72\x79"] === "\157\x70\145\156\163\x73\x6c")) {
            goto sx;
        }
        switch ($this->cryptParams["\164\x79\160\145"]) {
            case "\x73\x79\x6d\x6d\x65\x74\x72\151\143":
                return $this->encryptSymmetric($LF);
            case "\160\165\142\x6c\x69\x63":
                return $this->encryptPublic($LF);
            case "\160\x72\x69\x76\x61\x74\145":
                return $this->encryptPrivate($LF);
        }
        Ag:
        P0:
        sx:
    }
    public function decryptData($LF)
    {
        if (!($this->cryptParams["\x6c\151\142\x72\x61\x72\171"] === "\157\160\x65\x6e\x73\163\x6c")) {
            goto Hu;
        }
        switch ($this->cryptParams["\164\171\x70\x65"]) {
            case "\163\x79\155\x6d\145\x74\162\151\143":
                return $this->decryptSymmetric($LF);
            case "\x70\165\x62\x6c\x69\143":
                return $this->decryptPublic($LF);
            case "\x70\162\151\x76\x61\164\145":
                return $this->decryptPrivate($LF);
        }
        bd:
        hJ:
        Hu:
    }
    public function signData($LF)
    {
        switch ($this->cryptParams["\x6c\x69\x62\162\x61\162\x79"]) {
            case "\x6f\x70\145\156\163\163\x6c":
                return $this->signOpenSSL($LF);
            case self::HMAC_SHA1:
                return hash_hmac("\x73\x68\141\61", $LF, $this->key, true);
        }
        Iz:
        Ae:
    }
    public function verifySignature($LF, $Tm)
    {
        switch ($this->cryptParams["\154\151\x62\x72\141\x72\171"]) {
            case "\157\160\x65\156\x73\163\x6c":
                return $this->verifyOpenSSL($LF, $Tm);
            case self::HMAC_SHA1:
                $Ea = hash_hmac("\x73\150\x61\61", $LF, $this->key, true);
                return strcmp($Tm, $Ea) == 0;
        }
        h7:
        ga:
    }
    public function getAlgorithm()
    {
        return $this->cryptParams["\x6d\145\x74\150\x6f\144"];
    }
    public static function makeAsnSegment($Hm, $KW)
    {
        switch ($Hm) {
            case 0x2:
                if (!(ord($KW) > 0x7f)) {
                    goto Ur;
                }
                $KW = chr(0) . $KW;
                Ur:
                goto ZA;
            case 0x3:
                $KW = chr(0) . $KW;
                goto ZA;
        }
        Fx:
        ZA:
        $xf = strlen($KW);
        if ($xf < 128) {
            goto vR;
        }
        if ($xf < 0x100) {
            goto g1;
        }
        if ($xf < 0x10000) {
            goto EJ;
        }
        $cY = null;
        goto jt;
        EJ:
        $cY = sprintf("\45\x63\x25\143\x25\x63\45\x63\45\x73", $Hm, 0x82, $xf / 0x100, $xf % 0x100, $KW);
        jt:
        goto n3;
        g1:
        $cY = sprintf("\45\x63\x25\143\x25\x63\x25\x73", $Hm, 0x81, $xf, $KW);
        n3:
        goto Nd;
        vR:
        $cY = sprintf("\45\143\45\143\x25\163", $Hm, $xf, $KW);
        Nd:
        return $cY;
    }
    public static function convertRSA($HU, $fu)
    {
        $sl = self::makeAsnSegment(0x2, $fu);
        $T0 = self::makeAsnSegment(0x2, $HU);
        $Jy = self::makeAsnSegment(0x30, $T0 . $sl);
        $Zp = self::makeAsnSegment(0x3, $Jy);
        $ZF = pack("\110\x2a", "\x33\60\x30\x44\x30\66\60\x39\62\101\70\x36\x34\x38\x38\x36\106\67\60\104\60\x31\60\61\x30\x31\60\x35\60\x30");
        $R_ = self::makeAsnSegment(0x30, $ZF . $Zp);
        $Qf = base64_encode($R_);
        $bg = "\x2d\x2d\55\55\55\x42\x45\x47\x49\x4e\x20\x50\x55\x42\x4c\x49\x43\40\113\105\x59\55\x2d\55\55\x2d\12";
        $bU = 0;
        u0:
        if (!($kD = substr($Qf, $bU, 64))) {
            goto V9;
        }
        $bg = $bg . $kD . "\12";
        $bU += 64;
        goto u0;
        V9:
        return $bg . "\x2d\x2d\55\55\55\105\x4e\104\x20\x50\125\x42\114\111\x43\40\113\x45\x59\x2d\55\x2d\55\x2d\xa";
    }
    public function serializeKey($zd)
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
    public static function fromEncryptedKeyElement(DOMElement $Xf)
    {
        $jk = new XMLSecEnc();
        $jk->setNode($Xf);
        if ($Ek = $jk->locateKey()) {
            goto O_;
        }
        throw new Exception("\125\156\x61\x62\154\x65\x20\x74\x6f\x20\154\x6f\x63\141\x74\x65\40\141\x6c\x67\x6f\x72\151\x74\150\x6d\x20\x66\157\x72\40\x74\150\x69\163\x20\105\156\143\162\x79\160\x74\x65\x64\40\x4b\145\x79");
        O_:
        $Ek->isEncrypted = true;
        $Ek->encryptedCtx = $jk;
        XMLSecEnc::staticLocateKeyInfo($Ek, $Xf);
        return $Ek;
    }
}
class XMLSecEnc
{
    const template = "\x3c\170\x65\156\x63\x3a\105\x6e\143\x72\171\x70\164\x65\x64\x44\141\164\x61\40\170\155\154\x6e\x73\72\170\x65\156\143\75\47\150\x74\x74\160\72\57\x2f\x77\167\167\56\167\63\56\157\x72\147\57\62\x30\60\61\x2f\60\x34\57\x78\155\x6c\x65\x6e\143\43\x27\76\xd\12\40\40\x20\x3c\170\145\156\143\x3a\x43\x69\x70\150\x65\x72\x44\x61\164\x61\76\xd\xa\x20\x20\40\x20\40\x20\x3c\x78\x65\156\x63\72\x43\x69\160\150\145\x72\x56\x61\154\x75\x65\x3e\74\57\170\x65\x6e\x63\x3a\x43\x69\160\x68\x65\162\x56\x61\154\165\x65\x3e\15\xa\40\x20\40\74\57\x78\x65\156\143\x3a\103\151\x70\150\145\x72\x44\141\164\141\76\xd\xa\74\x2f\170\x65\x6e\x63\x3a\105\156\143\x72\x79\160\x74\145\144\104\x61\x74\141\x3e";
    const Element = "\150\164\164\x70\72\x2f\x2f\x77\167\167\x2e\x77\63\x2e\157\162\147\x2f\x32\60\60\61\x2f\x30\x34\57\x78\x6d\154\x65\x6e\x63\x23\105\154\145\x6d\x65\x6e\x74";
    const Content = "\x68\164\x74\160\x3a\57\57\x77\x77\x77\56\167\63\56\157\x72\x67\x2f\x32\60\60\61\57\x30\64\57\x78\155\154\145\x6e\x63\x23\103\x6f\x6e\x74\145\x6e\164";
    const URI = 3;
    const XMLENCNS = "\x68\x74\x74\x70\72\57\57\167\167\x77\56\167\63\56\x6f\162\147\57\62\60\x30\61\57\60\x34\57\170\x6d\x6c\x65\156\143\x23";
    private $encdoc = null;
    private $rawNode = null;
    public $type = null;
    public $encKey = null;
    private $references = array();
    public function __construct()
    {
        $this->_resetTemplate();
    }
    private function _resetTemplate()
    {
        $this->encdoc = new DOMDocument();
        $this->encdoc->loadXML(self::template);
    }
    public function addReference($Fg, $TV, $Hm)
    {
        if ($TV instanceof DOMNode) {
            goto Pm;
        }
        throw new Exception("\44\156\x6f\x64\145\x20\151\x73\40\x6e\x6f\164\x20\157\146\40\164\171\160\145\x20\x44\x4f\x4d\116\x6f\144\145");
        Pm:
        $x1 = $this->encdoc;
        $this->_resetTemplate();
        $cC = $this->encdoc;
        $this->encdoc = $x1;
        $wv = XMLSecurityDSig::generateGUID();
        $Xf = $cC->documentElement;
        $Xf->setAttribute("\x49\x64", $wv);
        $this->references[$Fg] = array("\156\157\x64\x65" => $TV, "\164\x79\x70\145" => $Hm, "\x65\156\x63\156\x6f\144\x65" => $cC, "\x72\x65\146\x75\162\151" => $wv);
    }
    public function setNode($TV)
    {
        $this->rawNode = $TV;
    }
    public function encryptNode($Ek, $I2 = true)
    {
        $LF = '';
        if (!empty($this->rawNode)) {
            goto qc;
        }
        throw new Exception("\x4e\157\x64\x65\x20\164\x6f\x20\x65\x6e\143\162\x79\160\x74\x20\x68\141\x73\40\156\157\164\x20\x62\145\145\156\40\163\145\x74");
        qc:
        if ($Ek instanceof XMLSecurityKey) {
            goto so;
        }
        throw new Exception("\111\x6e\x76\x61\154\x69\144\40\x4b\x65\171");
        so:
        $S9 = $this->rawNode->ownerDocument;
        $Hq = new DOMXPath($this->encdoc);
        $OY = $Hq->query("\x2f\170\145\156\x63\x3a\x45\156\x63\x72\x79\x70\x74\145\144\x44\141\x74\x61\57\x78\x65\x6e\143\x3a\103\x69\x70\x68\145\162\104\x61\x74\x61\57\170\145\x6e\x63\72\103\x69\160\150\x65\x72\126\141\x6c\165\x65");
        $ZZ = $OY->item(0);
        if (!($ZZ == null)) {
            goto gL;
        }
        throw new Exception("\x45\162\162\x6f\x72\x20\x6c\x6f\x63\x61\x74\151\x6e\x67\40\x43\151\160\x68\x65\162\x56\x61\154\165\x65\40\145\154\145\x6d\145\x6e\164\40\167\x69\164\150\x69\x6e\x20\164\x65\x6d\160\x6c\141\x74\145");
        gL:
        switch ($this->type) {
            case self::Element:
                $LF = $S9->saveXML($this->rawNode);
                $this->encdoc->documentElement->setAttribute("\124\x79\160\145", self::Element);
                goto T0;
            case self::Content:
                $L_ = $this->rawNode->childNodes;
                foreach ($L_ as $dW) {
                    $LF .= $S9->saveXML($dW);
                    xd:
                }
                uX:
                $this->encdoc->documentElement->setAttribute("\124\171\160\x65", self::Content);
                goto T0;
            default:
                throw new Exception("\124\x79\x70\145\x20\151\x73\40\x63\x75\162\x72\x65\156\x74\154\171\40\156\157\x74\40\163\x75\160\x70\157\x72\x74\145\x64");
        }
        Px:
        T0:
        $AK = $this->encdoc->documentElement->appendChild($this->encdoc->createElementNS(self::XMLENCNS, "\170\145\x6e\x63\72\105\x6e\x63\x72\171\160\164\151\x6f\x6e\115\x65\164\x68\157\x64"));
        $AK->setAttribute("\101\x6c\x67\x6f\162\151\164\x68\155", $Ek->getAlgorithm());
        $ZZ->parentNode->parentNode->insertBefore($AK, $ZZ->parentNode->parentNode->firstChild);
        $JM = base64_encode($Ek->encryptData($LF));
        $yX = $this->encdoc->createTextNode($JM);
        $ZZ->appendChild($yX);
        if ($I2) {
            goto v8;
        }
        return $this->encdoc->documentElement;
        goto dF;
        v8:
        switch ($this->type) {
            case self::Element:
                if (!($this->rawNode->nodeType == XML_DOCUMENT_NODE)) {
                    goto si;
                }
                return $this->encdoc;
                si:
                $R3 = $this->rawNode->ownerDocument->importNode($this->encdoc->documentElement, true);
                $this->rawNode->parentNode->replaceChild($R3, $this->rawNode);
                return $R3;
            case self::Content:
                $R3 = $this->rawNode->ownerDocument->importNode($this->encdoc->documentElement, true);
                cp:
                if (!$this->rawNode->firstChild) {
                    goto eo;
                }
                $this->rawNode->removeChild($this->rawNode->firstChild);
                goto cp;
                eo:
                $this->rawNode->appendChild($R3);
                return $R3;
        }
        D0:
        s5:
        dF:
    }
    public function encryptReferences($Ek)
    {
        $LG = $this->rawNode;
        $HH = $this->type;
        foreach ($this->references as $Fg => $SO) {
            $this->encdoc = $SO["\x65\156\143\x6e\157\x64\x65"];
            $this->rawNode = $SO["\x6e\157\x64\145"];
            $this->type = $SO["\x74\x79\x70\145"];
            try {
                $tx = $this->encryptNode($Ek);
                $this->references[$Fg]["\145\x6e\x63\156\157\144\x65"] = $tx;
            } catch (Exception $XU) {
                $this->rawNode = $LG;
                $this->type = $HH;
                throw $XU;
            }
            Dy:
        }
        U7:
        $this->rawNode = $LG;
        $this->type = $HH;
    }
    public function getCipherValue()
    {
        if (!empty($this->rawNode)) {
            goto Jy;
        }
        throw new Exception("\116\x6f\144\145\40\x74\157\x20\144\145\x63\x72\x79\160\164\40\150\x61\163\x20\156\157\164\40\142\x65\x65\156\40\x73\x65\164");
        Jy:
        $S9 = $this->rawNode->ownerDocument;
        $Hq = new DOMXPath($S9);
        $Hq->registerNamespace("\170\x6d\x6c\x65\x6e\x63\162", self::XMLENCNS);
        $bD = "\56\x2f\x78\155\x6c\x65\156\x63\162\72\x43\x69\x70\150\145\x72\x44\x61\164\x61\x2f\170\x6d\x6c\145\x6e\143\162\x3a\x43\x69\x70\150\x65\x72\126\x61\x6c\x75\x65";
        $Fa = $Hq->query($bD, $this->rawNode);
        $TV = $Fa->item(0);
        if ($TV) {
            goto Ll;
        }
        return null;
        Ll:
        return base64_decode($TV->nodeValue);
    }
    public function decryptNode($Ek, $I2 = true)
    {
        if ($Ek instanceof XMLSecurityKey) {
            goto rr;
        }
        throw new Exception("\111\156\x76\141\154\151\144\x20\113\x65\171");
        rr:
        $SI = $this->getCipherValue();
        if ($SI) {
            goto h1;
        }
        throw new Exception("\x43\x61\x6e\x6e\x6f\164\40\154\x6f\143\141\164\x65\x20\x65\156\143\x72\x79\160\164\145\144\x20\144\141\x74\x61");
        goto ao;
        h1:
        $gL = $Ek->decryptData($SI);
        if ($I2) {
            goto xm;
        }
        return $gL;
        goto Xg;
        xm:
        switch ($this->type) {
            case self::Element:
                $kT = new DOMDocument();
                $kT->loadXML($gL);
                if (!($this->rawNode->nodeType == XML_DOCUMENT_NODE)) {
                    goto em;
                }
                return $kT;
                em:
                $R3 = $this->rawNode->ownerDocument->importNode($kT->documentElement, true);
                $this->rawNode->parentNode->replaceChild($R3, $this->rawNode);
                return $R3;
            case self::Content:
                if ($this->rawNode->nodeType == XML_DOCUMENT_NODE) {
                    goto Zv;
                }
                $S9 = $this->rawNode->ownerDocument;
                goto l3;
                Zv:
                $S9 = $this->rawNode;
                l3:
                $tL = $S9->createDocumentFragment();
                $tL->appendXML($gL);
                $zd = $this->rawNode->parentNode;
                $zd->replaceChild($tL, $this->rawNode);
                return $zd;
            default:
                return $gL;
        }
        E7:
        Ko:
        Xg:
        ao:
    }
    public function encryptKey($Pt, $Jt, $Ts = true)
    {
        if (!(!$Pt instanceof XMLSecurityKey || !$Jt instanceof XMLSecurityKey)) {
            goto sw;
        }
        throw new Exception("\111\x6e\166\x61\154\151\144\x20\x4b\x65\x79");
        sw:
        $zg = base64_encode($Pt->encryptData($Jt->key));
        $Jp = $this->encdoc->documentElement;
        $pn = $this->encdoc->createElementNS(self::XMLENCNS, "\x78\x65\x6e\143\x3a\105\x6e\x63\162\171\x70\164\145\144\113\x65\x79");
        if ($Ts) {
            goto iH;
        }
        $this->encKey = $pn;
        goto xt;
        iH:
        $GQ = $Jp->insertBefore($this->encdoc->createElementNS("\x68\x74\164\160\72\x2f\x2f\x77\167\x77\x2e\x77\x33\x2e\157\x72\x67\x2f\x32\60\60\x30\57\x30\71\57\x78\155\154\x64\x73\151\x67\43", "\144\x73\151\x67\72\x4b\x65\171\111\156\146\x6f"), $Jp->firstChild);
        $GQ->appendChild($pn);
        xt:
        $AK = $pn->appendChild($this->encdoc->createElementNS(self::XMLENCNS, "\x78\x65\x6e\x63\x3a\105\x6e\x63\x72\171\x70\x74\x69\x6f\x6e\x4d\145\x74\x68\x6f\144"));
        $AK->setAttribute("\x41\154\147\157\162\151\164\x68\155", $Pt->getAlgorithm());
        if (empty($Pt->name)) {
            goto vX;
        }
        $GQ = $pn->appendChild($this->encdoc->createElementNS("\150\164\x74\160\x3a\x2f\x2f\x77\167\167\56\x77\63\x2e\157\162\147\x2f\x32\60\60\x30\57\x30\x39\x2f\x78\155\154\x64\163\x69\x67\43", "\144\x73\151\x67\x3a\x4b\x65\171\111\x6e\146\x6f"));
        $GQ->appendChild($this->encdoc->createElementNS("\150\164\x74\x70\x3a\x2f\x2f\x77\167\167\56\167\63\56\157\x72\x67\57\62\60\x30\60\57\x30\x39\x2f\170\155\154\144\x73\x69\147\43", "\x64\x73\151\x67\x3a\113\145\x79\116\141\155\x65", $Pt->name));
        vX:
        $XT = $pn->appendChild($this->encdoc->createElementNS(self::XMLENCNS, "\x78\145\x6e\x63\x3a\x43\151\160\x68\x65\162\x44\141\164\x61"));
        $XT->appendChild($this->encdoc->createElementNS(self::XMLENCNS, "\170\145\156\x63\x3a\103\x69\160\150\145\162\126\141\154\165\x65", $zg));
        if (!(is_array($this->references) && count($this->references) > 0)) {
            goto fm;
        }
        $y9 = $pn->appendChild($this->encdoc->createElementNS(self::XMLENCNS, "\170\145\x6e\143\x3a\122\145\146\x65\x72\145\156\143\145\x4c\151\163\164"));
        foreach ($this->references as $Fg => $SO) {
            $wv = $SO["\162\x65\x66\165\162\x69"];
            $lD = $y9->appendChild($this->encdoc->createElementNS(self::XMLENCNS, "\170\145\x6e\143\x3a\104\141\164\141\122\x65\146\145\x72\145\156\x63\145"));
            $lD->setAttribute("\x55\122\111", "\x23" . $wv);
            zI:
        }
        mo:
        fm:
        return;
    }
    public function decryptKey($pn)
    {
        if ($pn->isEncrypted) {
            goto xP;
        }
        throw new Exception("\x4b\x65\x79\40\151\x73\40\x6e\157\x74\40\x45\156\143\162\x79\160\164\x65\144");
        xP:
        if (!empty($pn->key)) {
            goto M1;
        }
        throw new Exception("\x4b\145\x79\x20\x69\163\40\155\x69\163\x73\151\156\x67\40\x64\x61\x74\141\40\164\x6f\x20\160\x65\162\146\157\x72\155\40\x74\150\x65\40\x64\145\143\162\171\160\x74\x69\x6f\156");
        M1:
        return $this->decryptNode($pn, false);
    }
    public function locateEncryptedData($Xf)
    {
        if ($Xf instanceof DOMDocument) {
            goto Be;
        }
        $S9 = $Xf->ownerDocument;
        goto Lg;
        Be:
        $S9 = $Xf;
        Lg:
        if (!$S9) {
            goto p1;
        }
        $Nj = new DOMXPath($S9);
        $bD = "\x2f\57\52\133\154\x6f\x63\x61\x6c\x2d\x6e\x61\155\x65\50\51\75\47\x45\156\143\162\171\160\164\x65\144\104\141\x74\141\47\40\x61\156\x64\40\156\141\155\145\163\160\141\143\x65\55\165\x72\x69\50\x29\75\x27" . self::XMLENCNS . "\47\135";
        $Fa = $Nj->query($bD);
        return $Fa->item(0);
        p1:
        return null;
    }
    public function locateKey($TV = null)
    {
        if (!empty($TV)) {
            goto Hz;
        }
        $TV = $this->rawNode;
        Hz:
        if ($TV instanceof DOMElement) {
            goto D3;
        }
        return null;
        D3:
        if (!($S9 = $TV->ownerDocument)) {
            goto QK;
        }
        $Nj = new DOMXPath($S9);
        $Nj->registerNamespace("\x78\155\x6c\x73\x65\143\145\x6e\x63", self::XMLENCNS);
        $bD = "\x2e\57\x2f\x78\x6d\154\163\x65\143\x65\156\143\x3a\105\156\x63\162\x79\x70\x74\x69\x6f\156\115\145\x74\150\x6f\x64";
        $Fa = $Nj->query($bD, $TV);
        if (!($xO = $Fa->item(0))) {
            goto db;
        }
        $Q2 = $xO->getAttribute("\x41\x6c\147\157\162\151\164\150\155");
        try {
            $Ek = new XMLSecurityKey($Q2, array("\x74\171\160\x65" => "\x70\x72\x69\x76\141\x74\x65"));
        } catch (Exception $XU) {
            return null;
        }
        return $Ek;
        db:
        QK:
        return null;
    }
    public static function staticLocateKeyInfo($eJ = null, $TV = null)
    {
        if (!(empty($TV) || !$TV instanceof DOMElement)) {
            goto cf;
        }
        return null;
        cf:
        $S9 = $TV->ownerDocument;
        if ($S9) {
            goto AG;
        }
        return null;
        AG:
        $Nj = new DOMXPath($S9);
        $Nj->registerNamespace("\170\x6d\x6c\x73\x65\143\145\x6e\143", self::XMLENCNS);
        $Nj->registerNamespace("\170\x6d\154\163\145\143\144\163\151\147", XMLSecurityDSig::XMLDSIGNS);
        $bD = "\x2e\x2f\x78\155\154\x73\145\x63\144\163\x69\x67\x3a\x4b\x65\x79\x49\x6e\146\x6f";
        $Fa = $Nj->query($bD, $TV);
        $xO = $Fa->item(0);
        if ($xO) {
            goto Vr;
        }
        return $eJ;
        Vr:
        foreach ($xO->childNodes as $dW) {
            switch ($dW->localName) {
                case "\x4b\x65\171\116\141\155\x65":
                    if (empty($eJ)) {
                        goto mb;
                    }
                    $eJ->name = $dW->nodeValue;
                    mb:
                    goto Dg;
                case "\113\x65\171\x56\141\154\x75\145":
                    foreach ($dW->childNodes as $XJ) {
                        switch ($XJ->localName) {
                            case "\x44\123\x41\x4b\x65\x79\x56\x61\154\165\x65":
                                throw new Exception("\x44\x53\101\113\145\x79\x56\x61\x6c\165\x65\40\143\165\x72\162\x65\156\x74\154\171\x20\x6e\x6f\164\x20\163\165\160\160\x6f\x72\164\x65\x64");
                            case "\122\x53\101\x4b\145\x79\126\x61\x6c\165\145":
                                $HU = null;
                                $fu = null;
                                if (!($Ut = $XJ->getElementsByTagName("\115\157\144\x75\x6c\x75\163")->item(0))) {
                                    goto Qb;
                                }
                                $HU = base64_decode($Ut->nodeValue);
                                Qb:
                                if (!($WV = $XJ->getElementsByTagName("\105\170\x70\157\x6e\x65\x6e\164")->item(0))) {
                                    goto fH;
                                }
                                $fu = base64_decode($WV->nodeValue);
                                fH:
                                if (!(empty($HU) || empty($fu))) {
                                    goto XZ;
                                }
                                throw new Exception("\115\x69\x73\x73\151\x6e\147\40\115\157\144\165\154\165\163\40\x6f\x72\x20\105\x78\160\x6f\156\x65\156\164");
                                XZ:
                                $Oq = XMLSecurityKey::convertRSA($HU, $fu);
                                $eJ->loadKey($Oq);
                                goto kM;
                        }
                        ml:
                        kM:
                        AL:
                    }
                    ZX:
                    goto Dg;
                case "\x52\x65\x74\162\x69\x65\166\141\x6c\x4d\x65\x74\150\157\144":
                    $Hm = $dW->getAttribute("\x54\171\x70\145");
                    if (!($Hm !== "\150\x74\x74\x70\x3a\x2f\x2f\167\167\x77\x2e\167\x33\56\157\x72\147\57\62\60\60\x31\57\60\x34\57\x78\155\154\145\x6e\x63\x23\x45\156\x63\162\171\x70\x74\145\x64\113\x65\x79")) {
                        goto Fp;
                    }
                    goto Dg;
                    Fp:
                    $yt = $dW->getAttribute("\125\x52\x49");
                    if (!($yt[0] !== "\x23")) {
                        goto RM;
                    }
                    goto Dg;
                    RM:
                    $kF = substr($yt, 1);
                    $bD = "\57\57\170\x6d\154\x73\145\143\145\x6e\143\x3a\x45\156\143\x72\x79\160\164\145\x64\x4b\x65\171\x5b\x40\111\144\75\47{$kF}\x27\135";
                    $Cb = $Nj->query($bD)->item(0);
                    if ($Cb) {
                        goto GE;
                    }
                    throw new Exception("\x55\156\x61\x62\154\145\40\x74\157\x20\x6c\157\x63\141\164\145\x20\x45\156\143\x72\171\160\164\x65\x64\113\x65\x79\x20\167\x69\x74\150\x20\x40\111\144\x3d\x27{$kF}\47\x2e");
                    GE:
                    return XMLSecurityKey::fromEncryptedKeyElement($Cb);
                case "\x45\x6e\143\162\x79\160\x74\x65\x64\113\145\x79":
                    return XMLSecurityKey::fromEncryptedKeyElement($dW);
                case "\x58\x35\x30\x39\104\x61\164\141":
                    if (!($yu = $dW->getElementsByTagName("\130\65\60\71\103\145\x72\x74\x69\146\151\x63\x61\164\145"))) {
                        goto D_;
                    }
                    if (!($yu->length > 0)) {
                        goto PE;
                    }
                    $zv = $yu->item(0)->textContent;
                    $zv = str_replace(array("\xd", "\xa", "\x20"), '', $zv);
                    $zv = "\x2d\55\55\55\x2d\x42\x45\x47\x49\116\40\103\x45\122\124\111\x46\x49\103\x41\124\x45\55\55\55\x2d\x2d\12" . chunk_split($zv, 64, "\12") . "\55\x2d\x2d\55\55\105\x4e\x44\x20\103\x45\122\124\x49\106\x49\103\101\124\105\55\55\55\55\x2d\12";
                    $eJ->loadKey($zv, false, true);
                    PE:
                    D_:
                    goto Dg;
            }
            xa:
            Dg:
            Gr:
        }
        PN:
        return $eJ;
    }
    public function locateKeyInfo($eJ = null, $TV = null)
    {
        if (!empty($TV)) {
            goto Ki;
        }
        $TV = $this->rawNode;
        Ki:
        return self::staticLocateKeyInfo($eJ, $TV);
    }
}
