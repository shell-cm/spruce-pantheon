<?php


namespace Drupal\miniorange_saml;

use DOMDocument;
use DOMElement;
use DOMXPath;
use Exception;
class XMLSecurityDSig
{
    const XMLDSIGNS = "\150\164\x74\x70\x3a\x2f\57\167\x77\x77\x2e\167\63\56\157\x72\x67\x2f\x32\60\x30\x30\x2f\60\71\57\170\x6d\x6c\x64\x73\x69\x67\x23";
    const SHA1 = "\150\x74\x74\x70\x3a\x2f\x2f\x77\x77\x77\56\167\63\56\157\162\147\x2f\x32\60\60\60\57\x30\71\57\x78\155\x6c\x64\x73\151\147\x23\163\x68\x61\61";
    const SHA256 = "\150\164\x74\160\x3a\x2f\x2f\x77\x77\167\56\x77\x33\56\x6f\x72\147\57\x32\x30\60\61\x2f\60\x34\57\x78\155\x6c\145\156\143\x23\x73\150\141\x32\65\x36";
    const SHA384 = "\150\164\164\160\72\57\x2f\167\167\167\56\x77\63\56\x6f\x72\x67\57\x32\60\x30\61\57\60\64\57\x78\155\154\144\163\x69\147\55\155\157\x72\145\x23\x73\x68\x61\63\x38\x34";
    const SHA512 = "\x68\x74\x74\x70\72\x2f\x2f\x77\167\x77\x2e\167\x33\56\x6f\162\x67\x2f\x32\60\x30\x31\x2f\60\64\x2f\x78\155\x6c\x65\x6e\143\x23\163\x68\x61\x35\x31\62";
    const RIPEMD160 = "\150\x74\x74\160\72\57\57\x77\x77\x77\56\167\x33\x2e\x6f\162\x67\x2f\x32\x30\x30\x31\57\x30\x34\x2f\x78\155\154\x65\x6e\x63\x23\162\151\x70\x65\155\144\61\x36\x30";
    const C14N = "\x68\x74\164\x70\x3a\x2f\57\x77\x77\x77\56\167\63\56\157\162\147\x2f\x54\122\x2f\x32\60\60\61\57\122\105\x43\55\170\155\x6c\x2d\143\x31\x34\156\x2d\x32\x30\60\x31\60\x33\x31\x35";
    const C14N_COMMENTS = "\x68\x74\164\160\x3a\57\57\x77\167\x77\56\167\63\56\x6f\162\x67\57\124\x52\57\62\x30\x30\x31\57\122\105\x43\55\170\155\154\x2d\x63\61\x34\156\x2d\x32\x30\60\x31\x30\x33\61\x35\43\x57\151\164\150\x43\157\x6d\155\145\x6e\x74\163";
    const EXC_C14N = "\x68\164\164\x70\72\x2f\57\x77\167\x77\56\167\63\56\x6f\162\147\x2f\62\x30\60\61\57\x31\x30\57\170\155\154\55\145\170\143\x2d\143\x31\64\156\x23";
    const EXC_C14N_COMMENTS = "\150\x74\164\x70\x3a\x2f\x2f\x77\x77\x77\56\167\x33\x2e\x6f\x72\147\57\62\60\60\61\57\x31\60\x2f\170\155\154\55\145\170\x63\55\x63\61\64\156\43\x57\151\x74\x68\x43\157\155\155\x65\156\164\163";
    const template = "\x3c\x64\x73\72\x53\151\147\156\x61\x74\165\162\145\40\170\155\154\x6e\x73\72\x64\x73\x3d\42\x68\x74\164\x70\72\x2f\57\x77\167\167\56\x77\63\x2e\x6f\162\147\57\x32\60\60\60\x2f\60\71\x2f\x78\x6d\x6c\x64\x73\151\147\43\42\x3e\xd\12\40\x20\74\144\163\72\123\151\147\156\x65\x64\x49\156\146\x6f\76\xd\12\40\40\40\40\x3c\144\x73\72\x53\151\x67\x6e\141\164\x75\162\145\115\145\164\x68\157\144\x20\57\76\xd\12\x20\40\x3c\57\x64\163\72\x53\151\147\156\145\144\111\156\146\x6f\x3e\xd\xa\74\x2f\144\x73\72\123\151\147\x6e\141\164\x75\162\x65\76";
    const BASE_TEMPLATE = "\x3c\x53\151\x67\x6e\x61\x74\x75\x72\145\40\170\155\154\x6e\x73\x3d\x22\x68\x74\164\x70\x3a\x2f\x2f\167\167\x77\x2e\167\63\x2e\157\162\147\x2f\x32\x30\x30\x30\57\60\x39\57\x78\155\154\x64\163\x69\x67\43\42\x3e\xd\xa\x20\40\x3c\123\x69\147\x6e\x65\x64\x49\x6e\x66\x6f\76\15\xa\40\40\x20\x20\74\x53\151\147\156\x61\x74\x75\x72\x65\x4d\x65\x74\150\157\144\x20\57\x3e\15\12\x20\x20\x3c\x2f\123\x69\x67\x6e\x65\144\111\x6e\x66\157\76\15\12\x3c\57\x53\x69\x67\156\141\164\x75\x72\145\76";
    public $sigNode = null;
    public $idKeys = array();
    public $idNS = array();
    private $signedInfo = null;
    private $xPathCtx = null;
    private $canonicalMethod = null;
    private $prefix = '';
    private $searchpfx = "\163\145\x63\144\163\x69\147";
    private $validatedNodes = null;
    public function __construct($I7 = "\x64\x73")
    {
        $rY = self::BASE_TEMPLATE;
        if (empty($I7)) {
            goto ku;
        }
        $this->prefix = $I7 . "\72";
        $so = array("\x3c\x53", "\x3c\x2f\x53", "\x78\155\154\x6e\x73\x3d");
        $I2 = array("\74{$I7}\72\123", "\x3c\57{$I7}\72\x53", "\x78\x6d\154\156\x73\x3a{$I7}\75");
        $rY = str_replace($so, $I2, $rY);
        ku:
        $aH = new DOMDocument();
        $aH->loadXML($rY);
        $this->sigNode = $aH->documentElement;
    }
    private function resetXPathObj()
    {
        $this->xPathCtx = null;
    }
    private function getXPathObj()
    {
        if (!(empty($this->xPathCtx) && !empty($this->sigNode))) {
            goto x2;
        }
        $Nj = new DOMXPath($this->sigNode->ownerDocument);
        $Nj->registerNamespace("\x73\145\x63\144\163\151\x67", self::XMLDSIGNS);
        $this->xPathCtx = $Nj;
        x2:
        return $this->xPathCtx;
    }
    public static function generateGUID($I7 = "\160\x66\170")
    {
        $rL = md5(uniqid(mt_rand(), true));
        $R7 = $I7 . substr($rL, 0, 8) . "\x2d" . substr($rL, 8, 4) . "\x2d" . substr($rL, 12, 4) . "\x2d" . substr($rL, 16, 4) . "\x2d" . substr($rL, 20, 12);
        return $R7;
    }
    public static function generate_GUID($I7 = "\x70\x66\170")
    {
        return self::generateGUID($I7);
    }
    public function locateSignature($rJ, $cp = 0)
    {
        if ($rJ instanceof DOMDocument) {
            goto eO;
        }
        $S9 = $rJ->ownerDocument;
        goto xc;
        eO:
        $S9 = $rJ;
        xc:
        if (!$S9) {
            goto ll;
        }
        $Nj = new DOMXPath($S9);
        $Nj->registerNamespace("\163\x65\143\x64\163\151\x67", self::XMLDSIGNS);
        $bD = "\x2e\57\57\163\145\x63\144\163\x69\147\x3a\x53\x69\x67\x6e\x61\164\x75\162\x65";
        $Fa = $Nj->query($bD, $rJ);
        $this->sigNode = $Fa->item($cp);
        return $this->sigNode;
        ll:
        return null;
    }
    public function createNewSignNode($Fg, $yX = null)
    {
        $S9 = $this->sigNode->ownerDocument;
        if (!is_null($yX)) {
            goto d9;
        }
        $TV = $S9->createElementNS(self::XMLDSIGNS, $this->prefix . $Fg);
        goto ty;
        d9:
        $TV = $S9->createElementNS(self::XMLDSIGNS, $this->prefix . $Fg, $yX);
        ty:
        return $TV;
    }
    public function setCanonicalMethod($XF)
    {
        switch ($XF) {
            case "\x68\164\x74\x70\72\x2f\x2f\x77\x77\x77\56\167\63\56\x6f\162\x67\x2f\124\x52\x2f\62\60\60\x31\57\122\105\103\x2d\x78\155\x6c\55\x63\61\64\156\55\62\x30\x30\x31\x30\x33\x31\65":
            case "\150\164\164\160\x3a\57\57\x77\167\167\56\x77\63\x2e\157\162\x67\57\124\x52\57\62\60\60\61\57\x52\105\x43\x2d\x78\155\154\x2d\x63\x31\x34\x6e\55\62\x30\60\61\60\x33\x31\x35\43\127\x69\x74\x68\x43\157\x6d\x6d\x65\156\x74\163":
            case "\150\164\164\x70\72\57\x2f\167\167\x77\x2e\x77\63\x2e\157\x72\x67\57\x32\x30\x30\61\x2f\61\x30\x2f\x78\155\154\x2d\x65\x78\x63\55\x63\61\x34\156\x23":
            case "\x68\164\x74\160\72\57\x2f\167\167\167\x2e\x77\x33\56\157\162\147\57\62\x30\x30\x31\x2f\61\x30\x2f\x78\155\x6c\x2d\145\170\143\55\x63\x31\x34\x6e\x23\127\151\164\x68\103\x6f\155\155\145\156\164\x73":
                $this->canonicalMethod = $XF;
                goto FL;
            default:
                throw new Exception("\x49\156\166\x61\x6c\151\144\40\103\141\x6e\157\x6e\x69\143\141\154\40\x4d\x65\164\x68\157\x64");
        }
        P2:
        FL:
        if (!($Nj = $this->getXPathObj())) {
            goto Ly;
        }
        $bD = "\x2e\57" . $this->searchpfx . "\72\123\151\147\156\x65\144\x49\156\146\x6f";
        $Fa = $Nj->query($bD, $this->sigNode);
        if (!($yC = $Fa->item(0))) {
            goto Ot;
        }
        $bD = "\x2e\x2f" . $this->searchpfx . "\x43\141\156\157\x6e\151\143\x61\154\151\172\141\x74\x69\157\156\115\x65\164\150\x6f\144";
        $Fa = $Nj->query($bD, $yC);
        if ($r5 = $Fa->item(0)) {
            goto Lv;
        }
        $r5 = $this->createNewSignNode("\x43\141\156\157\x6e\x69\143\x61\x6c\151\172\x61\x74\x69\x6f\x6e\115\145\164\x68\x6f\x64");
        $yC->insertBefore($r5, $yC->firstChild);
        Lv:
        $r5->setAttribute("\101\154\x67\x6f\x72\151\x74\150\155", $this->canonicalMethod);
        Ot:
        Ly:
    }
    private function canonicalizeData($TV, $YZ, $qU = null, $gT = null)
    {
        $Z7 = false;
        $CX = false;
        switch ($YZ) {
            case "\x68\x74\x74\160\72\x2f\x2f\x77\x77\x77\56\167\63\56\157\x72\147\x2f\124\122\57\x32\60\60\61\x2f\x52\x45\x43\55\170\x6d\x6c\x2d\x63\x31\x34\x6e\x2d\62\60\x30\x31\x30\x33\x31\x35":
                $Z7 = false;
                $CX = false;
                goto M7;
            case "\x68\164\164\x70\x3a\57\x2f\x77\167\167\56\x77\63\x2e\157\162\x67\x2f\x54\122\57\x32\60\60\61\x2f\122\105\103\55\170\x6d\154\x2d\143\x31\64\x6e\x2d\x32\x30\x30\x31\x30\x33\x31\65\43\127\151\x74\x68\x43\157\155\155\x65\x6e\x74\x73":
                $CX = true;
                goto M7;
            case "\150\x74\x74\x70\72\x2f\57\167\x77\x77\x2e\x77\63\x2e\x6f\162\147\x2f\62\x30\x30\x31\x2f\x31\60\57\x78\x6d\x6c\x2d\x65\x78\x63\x2d\143\x31\x34\156\x23":
                $Z7 = true;
                goto M7;
            case "\150\164\x74\x70\72\x2f\x2f\167\167\x77\56\167\x33\56\157\x72\147\x2f\62\x30\x30\61\x2f\61\60\57\170\155\x6c\x2d\x65\170\143\55\x63\x31\64\x6e\43\x57\x69\164\x68\103\x6f\155\155\145\x6e\x74\163":
                $Z7 = true;
                $CX = true;
                goto M7;
        }
        Sv:
        M7:
        if (!(is_null($qU) && $TV instanceof DOMNode && $TV->ownerDocument !== null && $TV->isSameNode($TV->ownerDocument->documentElement))) {
            goto NA;
        }
        $Xf = $TV;
        KP:
        if (!($mk = $Xf->previousSibling)) {
            goto tc;
        }
        if (!($mk->nodeType == XML_PI_NODE || $mk->nodeType == XML_COMMENT_NODE && $CX)) {
            goto pn;
        }
        goto tc;
        pn:
        $Xf = $mk;
        goto KP;
        tc:
        if (!($mk == null)) {
            goto Oh;
        }
        $TV = $TV->ownerDocument;
        Oh:
        NA:
        return $TV->C14N($Z7, $CX, $qU, $gT);
    }
    public function canonicalizeSignedInfo()
    {
        $S9 = $this->sigNode->ownerDocument;
        $YZ = null;
        if (!$S9) {
            goto B4;
        }
        $Nj = $this->getXPathObj();
        $bD = "\56\57\163\x65\x63\144\163\x69\147\x3a\123\151\x67\x6e\x65\144\111\x6e\146\157";
        $Fa = $Nj->query($bD, $this->sigNode);
        if (!($Th = $Fa->item(0))) {
            goto fG;
        }
        $bD = "\56\57\163\145\143\x64\163\151\x67\72\x43\x61\x6e\157\x6e\151\x63\x61\154\x69\x7a\141\x74\x69\x6f\x6e\x4d\x65\x74\x68\157\144";
        $Fa = $Nj->query($bD, $Th);
        if (!($r5 = $Fa->item(0))) {
            goto tE;
        }
        $YZ = $r5->getAttribute("\x41\x6c\147\157\162\151\164\x68\155");
        tE:
        $this->signedInfo = $this->canonicalizeData($Th, $YZ);
        return $this->signedInfo;
        fG:
        B4:
        return null;
    }
    public function calculateDigest($qC, $LF, $Pg = true)
    {
        switch ($qC) {
            case self::SHA1:
                $dj = "\163\150\x61\61";
                goto ff;
            case self::SHA256:
                $dj = "\x73\150\141\x32\x35\x36";
                goto ff;
            case self::SHA384:
                $dj = "\x73\150\x61\x33\70\x34";
                goto ff;
            case self::SHA512:
                $dj = "\163\150\141\x35\61\x32";
                goto ff;
            case self::RIPEMD160:
                $dj = "\162\x69\x70\x65\x6d\144\x31\x36\x30";
                goto ff;
            default:
                throw new Exception("\103\141\x6e\x6e\157\164\40\166\x61\x6c\x69\144\x61\x74\145\x20\144\x69\147\x65\163\x74\x3a\x20\125\x6e\163\165\160\160\x6f\x72\164\x65\x64\x20\x41\x6c\147\157\162\x69\x74\150\x6d\40\74{$qC}\76");
        }
        K5:
        ff:
        $vv = hash($dj, $LF, true);
        if (!$Pg) {
            goto qH;
        }
        $vv = base64_encode($vv);
        qH:
        return $vv;
    }
    public function validateDigest($Yb, $LF)
    {
        $Nj = new DOMXPath($Yb->ownerDocument);
        $Nj->registerNamespace("\163\x65\x63\x64\163\x69\x67", self::XMLDSIGNS);
        $bD = "\163\x74\162\151\x6e\147\x28\56\57\163\145\143\x64\163\151\x67\x3a\104\151\x67\145\163\164\115\145\x74\x68\x6f\144\x2f\x40\x41\154\147\157\x72\x69\x74\150\x6d\x29";
        $qC = $Nj->evaluate($bD, $Yb);
        $wP = $this->calculateDigest($qC, $LF, false);
        $bD = "\x73\x74\x72\x69\156\x67\x28\x2e\x2f\163\x65\x63\x64\x73\151\147\x3a\x44\151\x67\145\x73\164\126\x61\x6c\x75\145\51";
        $EY = $Nj->evaluate($bD, $Yb);
        return $wP == base64_decode($EY);
    }
    public function processTransforms($Yb, $YX, $VW = true)
    {
        $LF = $YX;
        $Nj = new DOMXPath($Yb->ownerDocument);
        $Nj->registerNamespace("\x73\145\x63\144\163\x69\147", self::XMLDSIGNS);
        $bD = "\x2e\57\163\145\x63\144\163\151\147\72\124\162\x61\156\163\x66\157\162\155\x73\57\163\x65\143\144\x73\x69\x67\x3a\124\x72\x61\156\163\x66\x6f\x72\155";
        $GY = $Nj->query($bD, $Yb);
        $qX = "\x68\x74\x74\x70\x3a\57\x2f\167\x77\x77\56\x77\x33\56\x6f\162\147\57\124\122\x2f\62\x30\60\x31\x2f\x52\105\103\x2d\x78\155\x6c\55\x63\x31\x34\156\x2d\62\x30\60\x31\60\x33\x31\x35";
        $qU = null;
        $gT = null;
        foreach ($GY as $Ty) {
            $x9 = $Ty->getAttribute("\x41\154\x67\157\162\151\x74\150\155");
            switch ($x9) {
                case "\x68\164\164\x70\72\x2f\x2f\167\x77\x77\56\167\63\x2e\x6f\x72\x67\x2f\x32\x30\60\x31\57\x31\60\57\x78\155\x6c\x2d\x65\x78\x63\55\143\61\x34\156\43":
                case "\x68\164\x74\160\x3a\57\x2f\167\x77\167\56\x77\63\x2e\x6f\x72\147\57\62\x30\x30\61\57\x31\60\x2f\170\x6d\154\55\145\x78\x63\55\x63\x31\x34\x6e\43\127\x69\x74\x68\x43\x6f\155\155\145\x6e\164\x73":
                    if (!$VW) {
                        goto T4;
                    }
                    $qX = $x9;
                    goto Kh;
                    T4:
                    $qX = "\x68\x74\164\160\72\57\x2f\167\x77\x77\x2e\167\63\x2e\x6f\x72\x67\x2f\x32\x30\60\x31\x2f\x31\x30\x2f\170\155\x6c\x2d\x65\x78\x63\55\143\61\x34\156\43";
                    Kh:
                    $TV = $Ty->firstChild;
                    Sb:
                    if (!$TV) {
                        goto f6;
                    }
                    if (!($TV->localName == "\111\x6e\143\154\165\x73\x69\x76\x65\116\141\x6d\x65\x73\x70\141\143\145\x73")) {
                        goto pe;
                    }
                    if (!($Oo = $TV->getAttribute("\120\x72\145\146\151\x78\x4c\x69\163\x74"))) {
                        goto Mx;
                    }
                    $Un = array();
                    $y2 = explode("\x20", $Oo);
                    foreach ($y2 as $Oo) {
                        $NW = trim($Oo);
                        if (empty($NW)) {
                            goto qY;
                        }
                        $Un[] = $NW;
                        qY:
                        sv:
                    }
                    ew:
                    if (!(count($Un) > 0)) {
                        goto Aj;
                    }
                    $gT = $Un;
                    Aj:
                    Mx:
                    goto f6;
                    pe:
                    $TV = $TV->nextSibling;
                    goto Sb;
                    f6:
                    goto e6;
                case "\150\164\164\160\x3a\57\57\167\x77\167\56\x77\63\x2e\157\162\147\x2f\x54\x52\57\62\x30\60\61\57\x52\x45\103\55\170\x6d\x6c\x2d\x63\x31\x34\x6e\x2d\62\x30\60\61\x30\x33\61\65":
                case "\x68\x74\x74\160\x3a\x2f\57\x77\x77\x77\56\x77\63\56\x6f\162\x67\57\124\x52\x2f\x32\x30\60\x31\57\x52\x45\103\x2d\x78\155\x6c\x2d\143\61\x34\x6e\x2d\x32\60\60\x31\x30\63\61\65\x23\127\151\x74\x68\103\157\155\x6d\x65\x6e\x74\x73":
                    if (!$VW) {
                        goto J7;
                    }
                    $qX = $x9;
                    goto It;
                    J7:
                    $qX = "\x68\x74\164\160\x3a\57\x2f\x77\167\167\56\x77\63\56\157\162\x67\57\x54\122\57\62\x30\x30\x31\x2f\x52\x45\x43\55\x78\x6d\154\x2d\143\61\64\x6e\x2d\62\60\x30\x31\60\63\61\65";
                    It:
                    goto e6;
                case "\150\x74\x74\x70\72\x2f\x2f\x77\x77\x77\x2e\167\63\x2e\157\x72\x67\57\124\122\57\x31\x39\71\71\57\122\105\103\x2d\170\x70\141\164\x68\x2d\61\x39\71\x39\61\x31\x31\66":
                    $TV = $Ty->firstChild;
                    K_:
                    if (!$TV) {
                        goto Jp;
                    }
                    if (!($TV->localName == "\130\x50\x61\x74\x68")) {
                        goto qh;
                    }
                    $qU = array();
                    $qU["\x71\165\145\162\x79"] = "\50\x2e\x2f\x2f\x2e\40\x7c\40\56\57\x2f\x40\x2a\x20\174\40\56\x2f\x2f\x6e\x61\155\x65\x73\x70\x61\143\145\x3a\x3a\x2a\x29\x5b" . $TV->nodeValue . "\135";
                    $xs["\156\x61\155\x65\x73\x70\141\x63\145\163"] = array();
                    $lw = $Nj->query("\56\x2f\156\141\x6d\145\x73\160\x61\143\x65\x3a\72\52", $TV);
                    foreach ($lw as $Fr) {
                        if (!($Fr->localName != "\x78\x6d\154")) {
                            goto Sz;
                        }
                        $qU["\156\141\155\145\x73\160\141\x63\x65\163"][$Fr->localName] = $Fr->nodeValue;
                        Sz:
                        c2:
                    }
                    tM:
                    goto Jp;
                    qh:
                    $TV = $TV->nextSibling;
                    goto K_;
                    Jp:
                    goto e6;
            }
            Rc:
            e6:
            G_:
        }
        i5:
        if (!$LF instanceof DOMElement) {
            goto eW;
        }
        $LF = $this->canonicalizeData($YX, $qX, $qU, $gT);
        eW:
        return $LF;
    }
    public function processRefNode($Yb)
    {
        $OF = null;
        $VW = true;
        if ($yt = $Yb->getAttribute("\125\122\x49")) {
            goto Wf;
        }
        $VW = false;
        $OF = $Yb->ownerDocument;
        goto aD;
        Wf:
        $jD = parse_url($yt);
        if (empty($jD["\160\141\164\150"])) {
            goto TC;
        }
        $OF = file_get_contents($jD);
        goto lW;
        TC:
        if ($XL = $jD["\146\x72\x61\x67\155\x65\x6e\164"]) {
            goto lB;
        }
        $OF = $Yb->ownerDocument;
        goto WD;
        lB:
        $VW = false;
        $Hq = new DOMXPath($Yb->ownerDocument);
        if (!($this->idNS && is_array($this->idNS))) {
            goto k5;
        }
        foreach ($this->idNS as $m1 => $Ar) {
            $Hq->registerNamespace($m1, $Ar);
            Q_:
        }
        QR:
        k5:
        $aU = "\100\x49\144\x3d\42" . $XL . "\42";
        if (!is_array($this->idKeys)) {
            goto SA;
        }
        foreach ($this->idKeys as $Id) {
            $aU .= "\40\x6f\x72\40\100{$Id}\x3d\x27{$XL}\47";
            JM:
        }
        lL:
        SA:
        $bD = "\x2f\57\52\x5b" . $aU . "\x5d";
        $OF = $Hq->query($bD)->item(0);
        WD:
        lW:
        aD:
        $LF = $this->processTransforms($Yb, $OF, $VW);
        if ($this->validateDigest($Yb, $LF)) {
            goto dJ;
        }
        return false;
        dJ:
        if (!$OF instanceof DOMElement) {
            goto iG;
        }
        if (!empty($XL)) {
            goto AI;
        }
        $this->validatedNodes[] = $OF;
        goto w8;
        AI:
        $this->validatedNodes[$XL] = $OF;
        w8:
        iG:
        return true;
    }
    public function getRefNodeID($Yb)
    {
        if (!($yt = $Yb->getAttribute("\x55\122\111"))) {
            goto ss;
        }
        $jD = parse_url($yt);
        if (!empty($jD["\160\x61\x74\x68"])) {
            goto Vx;
        }
        if (!($XL = $jD["\146\x72\141\147\155\x65\156\x74"])) {
            goto uG;
        }
        return $XL;
        uG:
        Vx:
        ss:
        return null;
    }
    public function getRefIDs()
    {
        $X3 = array();
        $Nj = $this->getXPathObj();
        $bD = "\56\x2f\x73\x65\x63\x64\x73\x69\x67\x3a\x53\151\x67\x6e\x65\144\x49\156\146\157\57\x73\x65\143\x64\163\x69\x67\x3a\x52\145\x66\145\x72\145\x6e\143\145";
        $Fa = $Nj->query($bD, $this->sigNode);
        if (!($Fa->length == 0)) {
            goto EU;
        }
        throw new Exception("\122\x65\146\145\x72\145\x6e\143\145\x20\x6e\157\144\145\x73\40\156\157\164\x20\x66\157\165\x6e\144");
        EU:
        foreach ($Fa as $Yb) {
            $X3[] = $this->getRefNodeID($Yb);
            wF:
        }
        R5:
        return $X3;
    }
    public function validateReference()
    {
        $Vy = $this->sigNode->ownerDocument->documentElement;
        if ($Vy->isSameNode($this->sigNode)) {
            goto kB;
        }
        if (!($this->sigNode->parentNode != null)) {
            goto ME;
        }
        $this->sigNode->parentNode->removeChild($this->sigNode);
        ME:
        kB:
        $Nj = $this->getXPathObj();
        $bD = "\x2e\57\x73\145\x63\144\x73\151\x67\72\123\151\x67\156\x65\x64\x49\x6e\x66\x6f\x2f\163\145\x63\x64\163\151\x67\x3a\122\145\146\145\162\145\156\143\145";
        $Fa = $Nj->query($bD, $this->sigNode);
        if (!($Fa->length == 0)) {
            goto rl;
        }
        throw new Exception("\122\x65\x66\145\x72\145\156\143\145\x20\156\157\x64\145\x73\x20\x6e\x6f\164\x20\146\x6f\165\156\x64");
        rl:
        $this->validatedNodes = array();
        foreach ($Fa as $Yb) {
            if ($this->processRefNode($Yb)) {
                goto nR;
            }
            $this->validatedNodes = null;
            throw new Exception("\122\x65\146\145\x72\x65\x6e\x63\x65\40\166\141\154\151\x64\x61\x74\x69\x6f\x6e\x20\x66\x61\x69\154\145\144");
            nR:
            Tz:
        }
        oo:
        return true;
    }
    private function addRefInternal($Nn, $TV, $x9, $D_ = null, $kk = null)
    {
        $I7 = null;
        $QE = null;
        $YW = "\111\x64";
        $Rq = true;
        $TK = false;
        if (!is_array($kk)) {
            goto XP;
        }
        $I7 = empty($kk["\x70\162\x65\x66\x69\170"]) ? null : $kk["\x70\162\145\146\x69\170"];
        $QE = empty($kk["\x70\162\x65\x66\x69\170\x5f\156\x73"]) ? null : $kk["\x70\x72\x65\146\x69\170\137\x6e\x73"];
        $YW = empty($kk["\x69\x64\137\156\141\x6d\145"]) ? "\111\144" : $kk["\x69\x64\137\x6e\141\155\x65"];
        $Rq = !isset($kk["\x6f\x76\x65\162\x77\162\151\164\145"]) ? true : (bool) $kk["\x6f\x76\145\162\167\162\x69\x74\x65"];
        $TK = !isset($kk["\146\157\x72\143\145\137\165\162\x69"]) ? false : (bool) $kk["\146\x6f\x72\x63\145\x5f\x75\x72\151"];
        XP:
        $AE = $YW;
        if (empty($I7)) {
            goto jn;
        }
        $AE = $I7 . "\x3a" . $AE;
        jn:
        $Yb = $this->createNewSignNode("\122\145\146\x65\x72\145\x6e\x63\145");
        $Nn->appendChild($Yb);
        if (!$TV instanceof DOMDocument) {
            goto ND;
        }
        if ($TK) {
            goto z8;
        }
        goto lM;
        ND:
        $yt = null;
        if ($Rq) {
            goto xH;
        }
        $yt = $QE ? $TV->getAttributeNS($QE, $YW) : $TV->getAttribute($YW);
        xH:
        if (!empty($yt)) {
            goto UM;
        }
        $yt = self::generateGUID();
        $TV->setAttributeNS($QE, $AE, $yt);
        UM:
        $Yb->setAttribute("\125\x52\111", "\43" . $yt);
        goto lM;
        z8:
        $Yb->setAttribute("\125\122\x49", '');
        lM:
        $sn = $this->createNewSignNode("\124\162\141\156\163\x66\x6f\162\155\x73");
        $Yb->appendChild($sn);
        if (is_array($D_)) {
            goto V2;
        }
        if (!empty($this->canonicalMethod)) {
            goto Il;
        }
        goto ec;
        V2:
        foreach ($D_ as $Ty) {
            $Sc = $this->createNewSignNode("\x54\x72\141\x6e\163\x66\x6f\162\155");
            $sn->appendChild($Sc);
            if (is_array($Ty) && !empty($Ty["\150\x74\164\x70\x3a\x2f\57\167\167\167\x2e\x77\x33\x2e\x6f\162\x67\x2f\x54\x52\x2f\x31\x39\x39\71\57\122\105\x43\55\x78\x70\x61\x74\150\x2d\x31\x39\71\x39\61\61\61\x36"]) && !empty($Ty["\x68\164\x74\160\x3a\x2f\57\167\167\167\x2e\167\x33\x2e\x6f\162\147\57\124\122\57\x31\71\x39\x39\x2f\x52\105\103\x2d\170\160\x61\x74\x68\55\x31\x39\x39\x39\61\x31\x31\x36"]["\x71\165\145\162\171"])) {
                goto U3;
            }
            $Sc->setAttribute("\101\154\147\x6f\x72\x69\164\150\155", $Ty);
            goto pl;
            U3:
            $Sc->setAttribute("\x41\x6c\147\157\162\151\x74\x68\x6d", "\150\164\164\x70\72\x2f\57\167\x77\x77\56\x77\x33\56\x6f\162\x67\x2f\124\122\57\x31\71\71\71\57\122\105\x43\x2d\170\160\x61\x74\150\55\61\71\71\71\61\61\x31\x36");
            $x0 = $this->createNewSignNode("\130\x50\141\164\150", $Ty["\150\164\x74\x70\x3a\x2f\x2f\x77\x77\x77\56\167\63\56\157\x72\147\x2f\x54\x52\57\61\71\71\71\57\122\x45\x43\55\x78\160\141\164\x68\55\x31\71\x39\71\x31\x31\61\x36"]["\161\x75\145\x72\x79"]);
            $Sc->appendChild($x0);
            if (empty($Ty["\x68\x74\164\x70\x3a\x2f\57\167\x77\167\56\x77\x33\56\157\162\147\x2f\x54\122\x2f\61\71\x39\x39\57\122\105\103\x2d\170\160\x61\x74\150\x2d\x31\x39\x39\71\61\x31\61\x36"]["\x6e\141\x6d\145\x73\160\x61\x63\145\x73"])) {
                goto Ep;
            }
            foreach ($Ty["\x68\x74\164\160\72\57\57\x77\x77\167\56\167\x33\56\x6f\162\147\x2f\124\x52\57\61\x39\x39\x39\57\x52\x45\103\55\x78\x70\141\x74\150\x2d\x31\x39\x39\71\61\x31\61\x36"]["\x6e\x61\155\x65\163\x70\141\x63\145\x73"] as $I7 => $Hw) {
                $x0->setAttributeNS("\x68\164\x74\160\x3a\x2f\57\167\167\167\56\167\x33\56\157\x72\147\57\62\60\60\60\x2f\x78\x6d\154\156\163\x2f", "\x78\x6d\x6c\x6e\x73\x3a{$I7}", $Hw);
                qE:
            }
            ev:
            Ep:
            pl:
            bU:
        }
        PW:
        goto ec;
        Il:
        $Sc = $this->createNewSignNode("\124\x72\x61\x6e\x73\146\x6f\x72\155");
        $sn->appendChild($Sc);
        $Sc->setAttribute("\101\x6c\x67\x6f\x72\151\164\x68\155", $this->canonicalMethod);
        ec:
        $xb = $this->processTransforms($Yb, $TV);
        $wP = $this->calculateDigest($x9, $xb);
        $J3 = $this->createNewSignNode("\x44\151\147\x65\x73\x74\115\x65\164\150\157\x64");
        $Yb->appendChild($J3);
        $J3->setAttribute("\x41\154\147\157\162\151\x74\150\x6d", $x9);
        $EY = $this->createNewSignNode("\x44\151\147\145\x73\x74\x56\x61\x6c\165\145", $wP);
        $Yb->appendChild($EY);
    }
    public function addReference($TV, $x9, $D_ = null, $kk = null)
    {
        if (!($Nj = $this->getXPathObj())) {
            goto ug;
        }
        $bD = "\x2e\57\x73\145\x63\x64\x73\x69\x67\x3a\123\x69\x67\156\x65\x64\x49\x6e\x66\x6f";
        $Fa = $Nj->query($bD, $this->sigNode);
        if (!($oQ = $Fa->item(0))) {
            goto cW;
        }
        $this->addRefInternal($oQ, $TV, $x9, $D_, $kk);
        cW:
        ug:
    }
    public function addReferenceList($uQ, $x9, $D_ = null, $kk = null)
    {
        if (!($Nj = $this->getXPathObj())) {
            goto LT;
        }
        $bD = "\x2e\57\163\x65\143\x64\163\x69\147\x3a\x53\x69\147\x6e\x65\144\x49\x6e\146\157";
        $Fa = $Nj->query($bD, $this->sigNode);
        if (!($oQ = $Fa->item(0))) {
            goto QH;
        }
        foreach ($uQ as $TV) {
            $this->addRefInternal($oQ, $TV, $x9, $D_, $kk);
            gi:
        }
        rD:
        QH:
        LT:
    }
    public function addObject($LF, $W_ = null, $bg = null)
    {
        $nx = $this->createNewSignNode("\117\x62\152\x65\143\x74");
        $this->sigNode->appendChild($nx);
        if (empty($W_)) {
            goto pa;
        }
        $nx->setAttribute("\x4d\x69\x6d\145\124\x79\160\x65", $W_);
        pa:
        if (empty($bg)) {
            goto N3;
        }
        $nx->setAttribute("\x45\156\x63\x6f\144\x69\156\147", $bg);
        N3:
        if ($LF instanceof DOMElement) {
            goto IG;
        }
        $u3 = $this->sigNode->ownerDocument->createTextNode($LF);
        goto oj;
        IG:
        $u3 = $this->sigNode->ownerDocument->importNode($LF, true);
        oj:
        $nx->appendChild($u3);
        return $nx;
    }
    public function locateKey($TV = null)
    {
        if (!empty($TV)) {
            goto i4;
        }
        $TV = $this->sigNode;
        i4:
        if ($TV instanceof DOMNode) {
            goto JG;
        }
        return null;
        JG:
        if (!($S9 = $TV->ownerDocument)) {
            goto MF;
        }
        $Nj = new DOMXPath($S9);
        $Nj->registerNamespace("\x73\x65\x63\144\x73\151\x67", self::XMLDSIGNS);
        $bD = "\x73\164\x72\x69\156\x67\x28\x2e\57\x73\x65\x63\144\163\151\147\72\x53\151\x67\156\145\x64\111\156\x66\x6f\x2f\163\145\143\x64\163\151\x67\72\x53\151\147\156\x61\164\x75\x72\x65\115\145\x74\150\x6f\144\x2f\100\101\x6c\x67\157\x72\151\164\150\155\51";
        $x9 = $Nj->evaluate($bD, $TV);
        if (!$x9) {
            goto Gx;
        }
        try {
            $Ek = new XMLSecurityKey($x9, array("\164\171\160\x65" => "\x70\165\x62\x6c\151\143"));
        } catch (Exception $XU) {
            return null;
        }
        return $Ek;
        Gx:
        MF:
        return null;
    }
    public function verify($Ek)
    {
        $S9 = $this->sigNode->ownerDocument;
        $Nj = new DOMXPath($S9);
        $Nj->registerNamespace("\x73\x65\143\144\x73\151\x67", self::XMLDSIGNS);
        $bD = "\x73\164\x72\151\156\147\50\56\x2f\x73\x65\143\x64\x73\151\147\x3a\x53\x69\147\x6e\141\x74\x75\x72\x65\126\141\154\165\x65\51";
        $hg = $Nj->evaluate($bD, $this->sigNode);
        if (!empty($hg)) {
            goto Qj;
        }
        throw new Exception("\x55\x6e\141\x62\154\x65\40\x74\x6f\40\x6c\157\x63\141\164\x65\x20\x53\151\147\156\x61\164\x75\x72\x65\126\141\x6c\x75\145");
        Qj:
        return $Ek->verifySignature($this->signedInfo, base64_decode($hg));
    }
    public function signData($Ek, $LF)
    {
        return $Ek->signData($LF);
    }
    public function sign($Ek, $il = null)
    {
        if (!($il != null)) {
            goto Ax;
        }
        $this->resetXPathObj();
        $this->appendSignature($il);
        $this->sigNode = $il->lastChild;
        Ax:
        if (!($Nj = $this->getXPathObj())) {
            goto Aw;
        }
        $bD = "\56\57\x73\145\x63\x64\x73\x69\147\x3a\123\151\x67\x6e\145\x64\111\x6e\x66\x6f";
        $Fa = $Nj->query($bD, $this->sigNode);
        if (!($oQ = $Fa->item(0))) {
            goto Y8;
        }
        $bD = "\x2e\57\163\x65\x63\x64\163\x69\147\x3a\x53\x69\x67\156\141\x74\x75\x72\145\115\145\x74\150\x6f\x64";
        $Fa = $Nj->query($bD, $oQ);
        $B9 = $Fa->item(0);
        $B9->setAttribute("\101\154\x67\157\x72\x69\x74\x68\155", $Ek->type);
        $LF = $this->canonicalizeData($oQ, $this->canonicalMethod);
        $hg = base64_encode($this->signData($Ek, $LF));
        $w2 = $this->createNewSignNode("\x53\x69\x67\156\141\164\x75\162\x65\x56\141\154\165\145", $hg);
        if ($hk = $oQ->nextSibling) {
            goto s3;
        }
        $this->sigNode->appendChild($w2);
        goto l1;
        s3:
        $hk->parentNode->insertBefore($w2, $hk);
        l1:
        Y8:
        Aw:
    }
    public function appendCert()
    {
    }
    public function appendKey($Ek, $zd = null)
    {
        $Ek->serializeKey($zd);
    }
    public function insertSignature($TV, $Xq = null)
    {
        $HT = $TV->ownerDocument;
        $Bb = $HT->importNode($this->sigNode, true);
        if ($Xq == null) {
            goto yT;
        }
        return $TV->insertBefore($Bb, $Xq);
        goto HH;
        yT:
        return $TV->insertBefore($Bb);
        HH:
    }
    public function appendSignature($Xs, $R8 = false)
    {
        $Xq = $R8 ? $Xs->firstChild : null;
        return $this->insertSignature($Xs, $Xq);
    }
    public static function get509XCert($Jw, $Zj = true)
    {
        $I9 = self::staticGet509XCerts($Jw, $Zj);
        if (empty($I9)) {
            goto Rm;
        }
        return $I9[0];
        Rm:
        return '';
    }
    public static function staticGet509XCerts($I9, $Zj = true)
    {
        if ($Zj) {
            goto da;
        }
        return array($I9);
        goto q4;
        da:
        $LF = '';
        $hC = array();
        $xi = explode("\12", $I9);
        $GU = false;
        foreach ($xi as $Jx) {
            if (!$GU) {
                goto Pw;
            }
            if (!(strncmp($Jx, "\55\x2d\55\x2d\55\105\x4e\x44\x20\x43\x45\122\x54\111\x46\x49\103\101\x54\105", 20) == 0)) {
                goto D4;
            }
            $GU = false;
            $hC[] = $LF;
            $LF = '';
            goto wE;
            D4:
            $LF .= trim($Jx);
            goto JT;
            Pw:
            if (!(strncmp($Jx, "\x2d\x2d\55\x2d\55\102\105\107\x49\116\40\103\x45\122\x54\x49\106\x49\103\x41\x54\x45", 22) == 0)) {
                goto vO;
            }
            $GU = true;
            vO:
            JT:
            wE:
        }
        Ry:
        return $hC;
        q4:
    }
    public static function staticAdd509Cert($yQ, $Jw, $Zj = true, $Hi = false, $Nj = null, $kk = null)
    {
        if (!$Hi) {
            goto Sx;
        }
        $Jw = file_get_contents($Jw);
        Sx:
        if ($yQ instanceof DOMElement) {
            goto qQ;
        }
        throw new Exception("\x49\x6e\166\x61\154\151\144\40\160\x61\162\x65\x6e\164\x20\x4e\157\x64\145\x20\x70\141\162\x61\x6d\145\164\145\162");
        qQ:
        $f5 = $yQ->ownerDocument;
        if (!empty($Nj)) {
            goto gt;
        }
        $Nj = new DOMXPath($yQ->ownerDocument);
        $Nj->registerNamespace("\163\145\x63\144\163\x69\x67", self::XMLDSIGNS);
        gt:
        $bD = "\x2e\57\163\x65\143\x64\163\151\147\x3a\113\x65\171\x49\156\x66\157";
        $Fa = $Nj->query($bD, $yQ);
        $GQ = $Fa->item(0);
        $Ov = '';
        if (!$GQ) {
            goto Nc;
        }
        $Oo = $GQ->lookupPrefix(self::XMLDSIGNS);
        if (empty($Oo)) {
            goto JI;
        }
        $Ov = $Oo . "\72";
        JI:
        goto PQ;
        Nc:
        $Oo = $yQ->lookupPrefix(self::XMLDSIGNS);
        if (empty($Oo)) {
            goto DY;
        }
        $Ov = $Oo . "\72";
        DY:
        $o2 = false;
        $GQ = $f5->createElementNS(self::XMLDSIGNS, $Ov . "\x4b\145\171\111\156\x66\x6f");
        $bD = "\56\57\x73\145\x63\x64\x73\151\147\x3a\x4f\x62\x6a\145\x63\164";
        $Fa = $Nj->query($bD, $yQ);
        if (!($LU = $Fa->item(0))) {
            goto Se;
        }
        $LU->parentNode->insertBefore($GQ, $LU);
        $o2 = true;
        Se:
        if ($o2) {
            goto nM;
        }
        $yQ->appendChild($GQ);
        nM:
        PQ:
        $I9 = self::staticGet509XCerts($Jw, $Zj);
        $KX = $f5->createElementNS(self::XMLDSIGNS, $Ov . "\130\65\60\x39\x44\x61\x74\x61");
        $GQ->appendChild($KX);
        $p3 = false;
        $Ir = false;
        if (!is_array($kk)) {
            goto dr;
        }
        if (empty($kk["\x69\x73\x73\165\145\x72\123\145\x72\151\141\154"])) {
            goto Jf;
        }
        $p3 = true;
        Jf:
        if (empty($kk["\163\165\142\152\145\x63\x74\x4e\141\x6d\145"])) {
            goto sF;
        }
        $Ir = true;
        sF:
        dr:
        foreach ($I9 as $pg) {
            if (!($p3 || $Ir)) {
                goto X1;
            }
            if (!($z1 = openssl_x509_parse("\55\55\x2d\55\x2d\x42\105\x47\111\x4e\40\103\105\122\x54\111\x46\111\103\101\x54\x45\x2d\55\55\55\x2d\xa" . chunk_split($pg, 64, "\12") . "\x2d\x2d\x2d\x2d\x2d\x45\116\104\x20\103\x45\x52\x54\x49\x46\111\x43\101\x54\105\x2d\x2d\x2d\x2d\x2d\12"))) {
                goto cs;
            }
            if (!($Ir && !empty($z1["\163\165\142\152\x65\143\x74"]))) {
                goto gF;
            }
            if (is_array($z1["\163\x75\x62\x6a\x65\x63\164"])) {
                goto X8;
            }
            $Kh = $z1["\x69\x73\x73\165\145\x72"];
            goto xg;
            X8:
            $b5 = array();
            foreach ($z1["\163\165\142\x6a\x65\143\x74"] as $eQ => $yX) {
                if (is_array($yX)) {
                    goto tF;
                }
                array_unshift($b5, "{$eQ}\x3d{$yX}");
                goto Dk;
                tF:
                foreach ($yX as $PT) {
                    array_unshift($b5, "{$eQ}\x3d{$PT}");
                    iq:
                }
                FO:
                Dk:
                Md:
            }
            ZB:
            $Kh = implode("\x2c", $b5);
            xg:
            $ub = $f5->createElementNS(self::XMLDSIGNS, $Ov . "\130\x35\x30\x39\x53\165\x62\152\145\143\x74\116\141\155\x65", $Kh);
            $KX->appendChild($ub);
            gF:
            if (!($p3 && !empty($z1["\151\163\163\165\x65\162"]) && !empty($z1["\163\145\162\151\x61\154\116\x75\x6d\x62\x65\162"]))) {
                goto Fi;
            }
            if (is_array($z1["\151\x73\x73\165\x65\162"])) {
                goto Ra;
            }
            $p1 = $z1["\x69\x73\x73\165\x65\x72"];
            goto iO;
            Ra:
            $b5 = array();
            foreach ($z1["\x69\163\163\x75\x65\162"] as $eQ => $yX) {
                array_unshift($b5, "{$eQ}\x3d{$yX}");
                zA:
            }
            u1:
            $p1 = implode("\x2c", $b5);
            iO:
            $L7 = $f5->createElementNS(self::XMLDSIGNS, $Ov . "\130\65\60\71\111\163\163\165\x65\162\123\145\162\151\141\154");
            $KX->appendChild($L7);
            $xS = $f5->createElementNS(self::XMLDSIGNS, $Ov . "\x58\x35\60\71\111\163\x73\165\x65\x72\x4e\141\155\x65", $p1);
            $L7->appendChild($xS);
            $xS = $f5->createElementNS(self::XMLDSIGNS, $Ov . "\130\x35\x30\71\x53\145\x72\151\x61\x6c\x4e\165\155\x62\145\x72", $z1["\x73\145\162\x69\141\154\116\x75\x6d\x62\145\x72"]);
            $L7->appendChild($xS);
            Fi:
            cs:
            X1:
            $uz = $f5->createElementNS(self::XMLDSIGNS, $Ov . "\x58\65\60\x39\x43\145\x72\164\x69\146\x69\x63\x61\x74\145", $pg);
            $KX->appendChild($uz);
            MD:
        }
        VL:
    }
    public function add509Cert($Jw, $Zj = true, $Hi = false, $kk = null)
    {
        if (!($Nj = $this->getXPathObj())) {
            goto lU;
        }
        self::staticAdd509Cert($this->sigNode, $Jw, $Zj, $Hi, $Nj, $kk);
        lU:
    }
    public function appendToKeyInfo($TV)
    {
        $yQ = $this->sigNode;
        $f5 = $yQ->ownerDocument;
        $Nj = $this->getXPathObj();
        if (!empty($Nj)) {
            goto Eb;
        }
        $Nj = new DOMXPath($yQ->ownerDocument);
        $Nj->registerNamespace("\x73\145\x63\144\x73\x69\147", self::XMLDSIGNS);
        Eb:
        $bD = "\x2e\x2f\x73\145\143\x64\163\x69\147\x3a\113\145\x79\111\156\x66\157";
        $Fa = $Nj->query($bD, $yQ);
        $GQ = $Fa->item(0);
        if ($GQ) {
            goto dy;
        }
        $Ov = '';
        $Oo = $yQ->lookupPrefix(self::XMLDSIGNS);
        if (empty($Oo)) {
            goto sD;
        }
        $Ov = $Oo . "\72";
        sD:
        $o2 = false;
        $GQ = $f5->createElementNS(self::XMLDSIGNS, $Ov . "\113\x65\x79\x49\x6e\146\x6f");
        $bD = "\x2e\57\x73\145\143\x64\163\151\x67\x3a\117\x62\x6a\145\143\x74";
        $Fa = $Nj->query($bD, $yQ);
        if (!($LU = $Fa->item(0))) {
            goto AC;
        }
        $LU->parentNode->insertBefore($GQ, $LU);
        $o2 = true;
        AC:
        if ($o2) {
            goto Ci;
        }
        $yQ->appendChild($GQ);
        Ci:
        dy:
        $GQ->appendChild($TV);
        return $GQ;
    }
    public function getValidatedNodes()
    {
        return $this->validatedNodes;
    }
}
