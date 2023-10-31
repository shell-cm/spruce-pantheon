<?php


namespace Drupal\miniorange_saml;

use DOMDocument;
use DOMElement;
use DOMNode;
use DOMXPath;
use Exception;
class XMLSecurityDSig
{
    const XMLDSIGNS = "\150\164\164\160\x3a\57\x2f\167\x77\167\56\167\63\x2e\157\162\147\x2f\x32\60\x30\60\x2f\x30\x39\57\170\155\x6c\x64\163\x69\147\x23";
    const SHA1 = "\x68\164\164\160\72\x2f\57\167\167\x77\x2e\x77\x33\x2e\x6f\162\147\57\62\x30\x30\60\x2f\x30\x39\x2f\170\155\154\x64\163\x69\147\43\163\150\141\61";
    const SHA256 = "\x68\164\164\x70\72\x2f\57\167\167\x77\56\167\x33\56\x6f\162\147\57\62\60\60\x31\x2f\60\x34\57\170\155\154\145\x6e\x63\43\163\150\x61\62\x35\x36";
    const SHA384 = "\x68\x74\x74\160\x3a\x2f\x2f\x77\x77\x77\x2e\x77\63\56\x6f\x72\147\57\62\60\x30\61\57\x30\64\57\x78\x6d\154\144\163\151\x67\x2d\155\x6f\x72\x65\43\x73\150\x61\63\70\64";
    const SHA512 = "\150\164\164\x70\x3a\x2f\57\167\x77\167\x2e\167\63\56\157\162\147\57\62\60\x30\61\57\60\64\x2f\x78\155\x6c\x65\156\143\x23\163\150\141\65\x31\62";
    const RIPEMD160 = "\150\164\x74\x70\72\57\x2f\x77\x77\167\x2e\167\x33\56\157\x72\147\57\x32\x30\60\x31\57\60\x34\57\170\155\x6c\145\x6e\143\x23\162\151\160\145\155\x64\x31\66\x30";
    const C14N = "\x68\164\164\160\72\x2f\57\167\167\167\x2e\x77\x33\56\x6f\162\x67\57\x54\x52\x2f\x32\60\60\x31\x2f\122\x45\x43\55\170\155\154\x2d\143\61\64\x6e\55\62\60\60\61\x30\63\61\x35";
    const C14N_COMMENTS = "\150\164\164\160\x3a\x2f\x2f\x77\x77\x77\56\167\63\x2e\x6f\162\147\57\124\122\x2f\x32\60\x30\x31\x2f\122\105\x43\55\x78\x6d\154\x2d\x63\61\64\156\55\x32\60\60\x31\x30\63\x31\65\x23\127\151\164\150\x43\x6f\155\x6d\x65\156\164\x73";
    const EXC_C14N = "\x68\164\164\160\72\57\x2f\x77\x77\x77\56\167\63\56\157\x72\x67\x2f\x32\x30\x30\x31\x2f\x31\x30\57\x78\155\154\x2d\145\170\x63\x2d\x63\x31\64\156\x23";
    const EXC_C14N_COMMENTS = "\150\164\x74\x70\72\x2f\x2f\x77\x77\167\56\x77\x33\x2e\157\162\147\x2f\62\x30\x30\x31\57\61\60\x2f\170\x6d\154\55\145\170\143\55\x63\x31\64\x6e\43\x57\151\164\x68\x43\157\x6d\x6d\x65\156\164\163";
    const template = "\74\x64\163\72\x53\x69\147\156\141\164\165\x72\x65\x20\170\x6d\x6c\156\163\72\144\163\x3d\42\x68\164\x74\160\72\x2f\57\167\x77\x77\x2e\x77\63\56\x6f\162\147\x2f\x32\x30\60\60\x2f\60\x39\57\170\x6d\x6c\144\163\151\147\43\x22\x3e\xa\x20\40\x3c\144\x73\x3a\x53\x69\147\x6e\145\144\111\x6e\x66\157\76\12\x20\40\x20\x20\x3c\x64\x73\72\x53\151\147\x6e\141\x74\x75\x72\145\115\x65\164\150\x6f\144\40\x2f\x3e\12\x20\x20\74\x2f\144\x73\72\x53\151\x67\156\145\144\x49\x6e\146\x6f\x3e\xa\74\x2f\x64\x73\72\123\151\x67\156\141\164\165\x72\x65\76";
    const BASE_TEMPLATE = "\74\x53\151\x67\x6e\141\x74\165\x72\145\x20\x78\x6d\x6c\156\x73\x3d\x22\x68\x74\x74\x70\x3a\57\57\167\167\167\x2e\167\x33\56\157\162\147\57\x32\60\60\60\x2f\60\x39\57\x78\155\x6c\144\163\151\147\43\x22\76\xa\40\40\74\x53\x69\x67\x6e\x65\x64\111\x6e\146\x6f\x3e\12\x20\x20\x20\x20\74\x53\x69\147\x6e\x61\x74\165\x72\145\x4d\145\x74\x68\x6f\144\x20\x2f\x3e\12\40\40\74\57\x53\151\147\156\x65\x64\111\x6e\x66\157\x3e\12\74\x2f\123\151\x67\x6e\x61\x74\x75\162\145\x3e";
    public $sigNode = null;
    public $idKeys = array();
    public $idNS = array();
    private $signedInfo = null;
    private $xPathCtx = null;
    private $canonicalMethod = null;
    private $prefix = '';
    private $searchpfx = "\x73\145\143\144\x73\x69\147";
    private $validatedNodes = null;
    public function __construct($sd = "\144\x73")
    {
        $IB = self::BASE_TEMPLATE;
        if (empty($sd)) {
            goto Hz;
        }
        $this->prefix = $sd . "\72";
        $Ax = array("\x3c\123", "\74\x2f\123", "\170\x6d\x6c\x6e\163\x3d");
        $Oj = array("\x3c{$sd}\72\x53", "\74\57{$sd}\x3a\x53", "\x78\155\x6c\x6e\163\72{$sd}\x3d");
        $IB = str_replace($Ax, $Oj, $IB);
        Hz:
        $E8 = new DOMDocument();
        $E8->loadXML($IB);
        $this->sigNode = $E8->documentElement;
    }
    private function resetXPathObj()
    {
        $this->xPathCtx = null;
    }
    private function getXPathObj()
    {
        if (!(empty($this->xPathCtx) && !empty($this->sigNode))) {
            goto eq;
        }
        $Uk = new DOMXPath($this->sigNode->ownerDocument);
        $Uk->registerNamespace("\x73\x65\x63\144\163\151\x67", self::XMLDSIGNS);
        $this->xPathCtx = $Uk;
        eq:
        return $this->xPathCtx;
    }
    public static function generateGUID($sd = "\160\146\x78")
    {
        $qF = md5(uniqid(mt_rand(), true));
        $lT = $sd . substr($qF, 0, 8) . "\55" . substr($qF, 8, 4) . "\x2d" . substr($qF, 12, 4) . "\x2d" . substr($qF, 16, 4) . "\55" . substr($qF, 20, 12);
        return $lT;
    }
    public static function generate_GUID($sd = "\160\x66\170")
    {
        return self::generateGUID($sd);
    }
    public function locateSignature($nn, $UK = 0)
    {
        if ($nn instanceof DOMDocument) {
            goto sf;
        }
        $NW = $nn->ownerDocument;
        goto PO;
        sf:
        $NW = $nn;
        PO:
        if (!$NW) {
            goto tE;
        }
        $Uk = new DOMXPath($NW);
        $Uk->registerNamespace("\163\145\x63\144\163\151\147", self::XMLDSIGNS);
        $BJ = "\x2e\x2f\57\x73\x65\x63\x64\163\151\147\72\123\151\147\x6e\141\164\165\x72\145";
        $jM = $Uk->query($BJ, $nn);
        $this->sigNode = $jM->item($UK);
        $BJ = "\56\57\163\145\143\x64\163\x69\x67\72\x53\151\147\156\145\x64\111\156\x66\157";
        $jM = $Uk->query($BJ, $this->sigNode);
        if (!($jM->length > 1)) {
            goto ID;
        }
        throw new Exception("\111\x6e\166\x61\x6c\151\x64\40\x73\164\x72\x75\x63\x74\165\162\145\40\x2d\40\x54\x6f\x6f\x20\x6d\141\x6e\171\40\123\151\147\x6e\145\x64\111\x6e\146\x6f\x20\145\x6c\145\x6d\145\x6e\x74\x73\40\x66\157\x75\156\144");
        ID:
        return $this->sigNode;
        tE:
        return null;
    }
    public function createNewSignNode($KC, $Ox = null)
    {
        $NW = $this->sigNode->ownerDocument;
        if (!is_null($Ox)) {
            goto S1;
        }
        $Ci = $NW->createElementNS(self::XMLDSIGNS, $this->prefix . $KC);
        goto tw;
        S1:
        $Ci = $NW->createElementNS(self::XMLDSIGNS, $this->prefix . $KC, $Ox);
        tw:
        return $Ci;
    }
    public function setCanonicalMethod($gm)
    {
        switch ($gm) {
            case "\150\x74\164\160\x3a\57\57\167\x77\x77\56\167\x33\56\x6f\x72\147\x2f\124\122\x2f\62\60\60\x31\57\x52\105\103\x2d\170\155\154\x2d\143\x31\64\x6e\x2d\62\60\x30\61\x30\63\61\65":
            case "\150\x74\164\160\x3a\57\57\167\x77\167\x2e\x77\63\56\157\x72\147\x2f\124\x52\x2f\x32\x30\60\x31\57\x52\105\x43\55\x78\x6d\x6c\55\x63\61\64\x6e\x2d\62\60\x30\x31\x30\x33\61\65\x23\x57\x69\164\x68\103\x6f\x6d\155\145\x6e\164\x73":
            case "\x68\x74\x74\x70\x3a\x2f\57\167\x77\x77\x2e\x77\x33\56\x6f\x72\x67\57\x32\x30\x30\61\57\61\x30\57\170\x6d\154\x2d\145\x78\x63\x2d\143\x31\x34\156\43":
            case "\150\x74\x74\160\72\x2f\57\x77\167\167\56\x77\63\x2e\157\x72\x67\57\62\x30\60\x31\57\x31\x30\57\x78\155\x6c\x2d\145\170\143\x2d\143\x31\64\156\x23\x57\151\x74\x68\x43\157\x6d\155\145\156\x74\163":
                $this->canonicalMethod = $gm;
                goto vO;
            default:
                throw new Exception("\x49\156\x76\141\154\151\144\40\103\x61\x6e\157\156\151\x63\x61\154\40\x4d\x65\x74\150\157\144");
        }
        IV:
        vO:
        if (!($Uk = $this->getXPathObj())) {
            goto GE;
        }
        $BJ = "\56\x2f" . $this->searchpfx . "\72\x53\151\x67\156\x65\144\111\156\146\157";
        $jM = $Uk->query($BJ, $this->sigNode);
        if (!($Hl = $jM->item(0))) {
            goto dR;
        }
        $BJ = "\x2e\x2f" . $this->searchpfx . "\x43\x61\x6e\x6f\156\x69\143\141\154\151\172\x61\x74\x69\x6f\156\x4d\145\x74\x68\157\x64";
        $jM = $Uk->query($BJ, $Hl);
        if ($rz = $jM->item(0)) {
            goto Lp;
        }
        $rz = $this->createNewSignNode("\x43\141\156\157\x6e\x69\143\x61\154\x69\x7a\x61\x74\151\157\x6e\115\145\x74\150\x6f\x64");
        $Hl->insertBefore($rz, $Hl->firstChild);
        Lp:
        $rz->setAttribute("\101\154\147\x6f\x72\x69\x74\150\x6d", $this->canonicalMethod);
        dR:
        GE:
    }
    private function canonicalizeData($Ci, $d_, $UU = null, $if = null)
    {
        $vj = false;
        $u5 = false;
        switch ($d_) {
            case "\x68\x74\x74\x70\x3a\57\x2f\167\167\167\56\x77\x33\x2e\x6f\162\147\57\124\x52\x2f\62\60\x30\x31\x2f\x52\x45\x43\55\x78\x6d\x6c\55\143\x31\64\156\55\x32\60\x30\61\x30\63\x31\x35":
                $vj = false;
                $u5 = false;
                goto nY;
            case "\x68\164\164\x70\x3a\57\x2f\x77\x77\x77\x2e\x77\x33\56\x6f\x72\x67\57\124\122\57\x32\60\x30\61\57\122\x45\103\x2d\170\155\x6c\x2d\x63\61\64\x6e\x2d\62\60\60\61\x30\63\61\x35\x23\x57\151\x74\x68\103\157\155\155\145\x6e\164\163":
                $u5 = true;
                goto nY;
            case "\x68\x74\x74\x70\72\x2f\x2f\x77\167\167\56\167\63\56\x6f\162\x67\x2f\62\x30\x30\x31\57\x31\x30\57\170\x6d\x6c\55\145\x78\143\55\x63\61\64\x6e\43":
                $vj = true;
                goto nY;
            case "\150\x74\164\160\72\x2f\57\x77\x77\167\56\167\63\56\157\x72\x67\57\62\60\x30\x31\57\61\60\x2f\x78\x6d\154\55\x65\x78\143\x2d\x63\61\x34\156\43\x57\151\164\150\x43\x6f\x6d\155\x65\x6e\x74\163":
                $vj = true;
                $u5 = true;
                goto nY;
        }
        h9:
        nY:
        if (!(is_null($UU) && $Ci instanceof DOMNode && $Ci->ownerDocument !== null && $Ci->isSameNode($Ci->ownerDocument->documentElement))) {
            goto lB;
        }
        $cJ = $Ci;
        tf:
        if (!($Kk = $cJ->previousSibling)) {
            goto d6;
        }
        if (!($Kk->nodeType == XML_PI_NODE || $Kk->nodeType == XML_COMMENT_NODE && $u5)) {
            goto C7;
        }
        goto d6;
        C7:
        $cJ = $Kk;
        goto tf;
        d6:
        if (!($Kk == null)) {
            goto uW;
        }
        $Ci = $Ci->ownerDocument;
        uW:
        lB:
        return $Ci->C14N($vj, $u5, $UU, $if);
    }
    public function canonicalizeSignedInfo()
    {
        $NW = $this->sigNode->ownerDocument;
        $d_ = null;
        if (!$NW) {
            goto uP;
        }
        $Uk = $this->getXPathObj();
        $BJ = "\56\57\x73\145\143\x64\x73\151\x67\72\x53\151\x67\x6e\145\144\111\156\x66\x6f";
        $jM = $Uk->query($BJ, $this->sigNode);
        if (!($jM->length > 1)) {
            goto RU;
        }
        throw new Exception("\111\x6e\166\141\154\151\144\40\163\164\162\165\143\x74\165\x72\145\40\x2d\x20\124\157\x6f\x20\155\x61\x6e\171\40\x53\x69\x67\x6e\x65\144\x49\x6e\146\157\x20\x65\154\x65\x6d\x65\x6e\x74\163\40\x66\x6f\165\x6e\144");
        RU:
        if (!($Gh = $jM->item(0))) {
            goto No;
        }
        $BJ = "\x2e\57\163\x65\x63\x64\x73\x69\147\72\103\141\156\157\156\151\143\141\x6c\x69\172\x61\164\151\157\x6e\x4d\145\164\x68\x6f\x64";
        $jM = $Uk->query($BJ, $Gh);
        $if = null;
        if (!($rz = $jM->item(0))) {
            goto WR;
        }
        $d_ = $rz->getAttribute("\101\154\x67\x6f\162\x69\164\150\155");
        foreach ($rz->childNodes as $Ci) {
            if (!($Ci->localName == "\111\156\143\x6c\165\163\x69\166\x65\x4e\x61\x6d\x65\x73\x70\141\143\x65\x73")) {
                goto G0;
            }
            if (!($UZ = $Ci->getAttribute("\x50\162\x65\146\151\170\114\x69\x73\164"))) {
                goto ur;
            }
            $ax = array_filter(explode("\x20", $UZ));
            if (!(count($ax) > 0)) {
                goto Mx;
            }
            $if = array_merge($if ? $if : array(), $ax);
            Mx:
            ur:
            G0:
            I9:
        }
        oW:
        WR:
        $this->signedInfo = $this->canonicalizeData($Gh, $d_, null, $if);
        return $this->signedInfo;
        No:
        uP:
        return null;
    }
    public function calculateDigest($yx, $F9, $Kl = true)
    {
        switch ($yx) {
            case self::SHA1:
                $Qb = "\x73\x68\141\61";
                goto Dj;
            case self::SHA256:
                $Qb = "\163\150\x61\x32\65\x36";
                goto Dj;
            case self::SHA384:
                $Qb = "\x73\150\141\63\x38\x34";
                goto Dj;
            case self::SHA512:
                $Qb = "\x73\150\141\x35\x31\62";
                goto Dj;
            case self::RIPEMD160:
                $Qb = "\162\151\160\x65\155\144\61\66\x30";
                goto Dj;
            default:
                throw new Exception("\x43\141\156\x6e\x6f\x74\40\x76\141\154\151\x64\x61\x74\x65\x20\144\151\x67\x65\163\164\x3a\40\x55\x6e\163\165\x70\x70\x6f\x72\164\145\x64\x20\x41\x6c\x67\x6f\162\x69\x74\150\x6d\40\x3c{$yx}\x3e");
        }
        w7:
        Dj:
        $jA = hash($Qb, $F9, true);
        if (!$Kl) {
            goto KY;
        }
        $jA = base64_encode($jA);
        KY:
        return $jA;
    }
    public function validateDigest($wm, $F9)
    {
        $Uk = new DOMXPath($wm->ownerDocument);
        $Uk->registerNamespace("\163\x65\x63\x64\x73\151\x67", self::XMLDSIGNS);
        $BJ = "\x73\164\162\x69\156\147\x28\x2e\57\x73\145\x63\144\163\x69\x67\72\x44\151\x67\145\163\164\x4d\145\164\x68\x6f\x64\57\x40\101\154\x67\x6f\162\151\164\x68\x6d\x29";
        $yx = $Uk->evaluate($BJ, $wm);
        $CB = $this->calculateDigest($yx, $F9, false);
        $BJ = "\x73\164\x72\x69\156\x67\50\x2e\57\x73\x65\x63\144\x73\151\x67\72\104\x69\147\x65\163\164\x56\141\x6c\x75\145\x29";
        $PC = $Uk->evaluate($BJ, $wm);
        return $CB === base64_decode($PC);
    }
    public function processTransforms($wm, $F0, $D3 = true)
    {
        $F9 = $F0;
        $Uk = new DOMXPath($wm->ownerDocument);
        $Uk->registerNamespace("\163\145\143\144\x73\x69\147", self::XMLDSIGNS);
        $BJ = "\56\57\x73\145\x63\144\163\151\x67\72\x54\162\141\156\163\x66\x6f\162\x6d\163\x2f\x73\145\143\x64\163\151\147\72\x54\162\141\156\163\146\157\162\x6d";
        $E9 = $Uk->query($BJ, $wm);
        $XM = "\150\x74\x74\x70\72\x2f\x2f\167\x77\x77\56\x77\x33\x2e\x6f\x72\147\57\124\122\x2f\x32\60\60\61\x2f\122\x45\103\55\x78\x6d\154\x2d\x63\61\x34\156\x2d\x32\x30\x30\x31\x30\x33\x31\65";
        $UU = null;
        $if = null;
        foreach ($E9 as $NK) {
            $af = $NK->getAttribute("\101\154\147\157\162\x69\164\150\155");
            switch ($af) {
                case "\x68\x74\x74\x70\x3a\x2f\57\x77\x77\167\x2e\x77\x33\56\157\162\147\57\62\x30\x30\61\x2f\x31\x30\x2f\170\x6d\x6c\x2d\x65\170\143\x2d\x63\x31\x34\x6e\x23":
                case "\150\x74\164\160\72\x2f\57\167\x77\167\56\x77\63\56\157\162\147\x2f\62\x30\60\x31\57\x31\x30\x2f\170\155\x6c\x2d\145\x78\143\x2d\x63\61\64\156\x23\127\x69\x74\x68\103\x6f\x6d\155\x65\156\164\163":
                    if (!$D3) {
                        goto xA;
                    }
                    $XM = $af;
                    goto p9;
                    xA:
                    $XM = "\150\164\x74\x70\x3a\x2f\57\167\x77\x77\x2e\167\x33\x2e\x6f\x72\x67\57\62\x30\60\x31\57\x31\60\x2f\x78\x6d\154\x2d\145\170\143\55\143\61\64\156\x23";
                    p9:
                    $Ci = $NK->firstChild;
                    Id:
                    if (!$Ci) {
                        goto S0;
                    }
                    if (!($Ci->localName == "\x49\156\x63\x6c\165\x73\x69\x76\145\x4e\x61\155\x65\163\160\x61\x63\x65\163")) {
                        goto H3;
                    }
                    if (!($UZ = $Ci->getAttribute("\x50\162\x65\x66\151\170\114\151\x73\x74"))) {
                        goto RR;
                    }
                    $ax = array();
                    $Wl = explode("\40", $UZ);
                    foreach ($Wl as $UZ) {
                        $Ml = trim($UZ);
                        if (empty($Ml)) {
                            goto Om;
                        }
                        $ax[] = $Ml;
                        Om:
                        AW:
                    }
                    QD:
                    if (!(count($ax) > 0)) {
                        goto x1;
                    }
                    $if = $ax;
                    x1:
                    RR:
                    goto S0;
                    H3:
                    $Ci = $Ci->nextSibling;
                    goto Id;
                    S0:
                    goto yU;
                case "\x68\164\164\160\72\x2f\57\167\167\x77\56\167\x33\x2e\x6f\x72\147\57\x54\122\x2f\x32\x30\x30\61\57\x52\x45\x43\55\x78\x6d\x6c\x2d\x63\61\64\156\55\x32\x30\60\61\x30\x33\61\65":
                case "\x68\x74\x74\x70\72\57\57\167\x77\167\x2e\167\63\56\x6f\x72\147\57\124\122\x2f\x32\60\x30\61\57\x52\105\x43\55\170\x6d\154\x2d\x63\61\64\x6e\x2d\62\60\x30\x31\60\63\61\65\43\127\x69\164\x68\103\x6f\155\x6d\x65\156\x74\163":
                    if (!$D3) {
                        goto kk;
                    }
                    $XM = $af;
                    goto hg;
                    kk:
                    $XM = "\150\x74\x74\x70\x3a\x2f\57\x77\x77\x77\x2e\167\x33\56\157\x72\147\57\x54\x52\x2f\x32\x30\60\61\x2f\x52\x45\103\55\x78\155\154\55\143\x31\64\156\55\62\60\x30\x31\x30\63\61\x35";
                    hg:
                    goto yU;
                case "\150\x74\164\160\72\57\x2f\x77\167\x77\56\x77\x33\x2e\x6f\x72\x67\57\124\122\57\61\x39\x39\71\x2f\122\105\103\x2d\x78\160\x61\x74\150\x2d\x31\x39\71\x39\61\61\61\x36":
                    $Ci = $NK->firstChild;
                    M3:
                    if (!$Ci) {
                        goto Nt;
                    }
                    if (!($Ci->localName == "\x58\120\141\x74\x68")) {
                        goto XB;
                    }
                    $UU = array();
                    $UU["\x71\x75\x65\162\171"] = "\x28\56\57\x2f\56\x20\x7c\x20\x2e\x2f\57\x40\x2a\x20\x7c\40\56\57\x2f\x6e\x61\155\x65\x73\x70\141\143\x65\72\72\52\x29\x5b" . $Ci->nodeValue . "\x5d";
                    $UU["\156\141\155\x65\163\160\x61\x63\x65\163"] = array();
                    $Af = $Uk->query("\56\x2f\156\x61\155\145\163\160\x61\x63\145\72\x3a\x2a", $Ci);
                    foreach ($Af as $P1) {
                        if (!($P1->localName != "\170\155\x6c")) {
                            goto wu;
                        }
                        $UU["\x6e\141\x6d\145\x73\160\x61\143\x65\x73"][$P1->localName] = $P1->nodeValue;
                        wu:
                        dm:
                    }
                    Pc:
                    goto Nt;
                    XB:
                    $Ci = $Ci->nextSibling;
                    goto M3;
                    Nt:
                    goto yU;
            }
            nN:
            yU:
            yX:
        }
        Bc:
        if (!$F9 instanceof DOMNode) {
            goto KN;
        }
        $F9 = $this->canonicalizeData($F0, $XM, $UU, $if);
        KN:
        return $F9;
    }
    public function processRefNode($wm)
    {
        $aB = null;
        $D3 = true;
        if ($YT = $wm->getAttribute("\x55\x52\x49")) {
            goto bK;
        }
        $D3 = false;
        $aB = $wm->ownerDocument;
        goto W5;
        bK:
        $TN = parse_url($YT);
        if (!empty($TN["\160\141\164\150"])) {
            goto OS;
        }
        if ($DY = $TN["\x66\162\141\147\155\145\156\x74"]) {
            goto cs;
        }
        $aB = $wm->ownerDocument;
        goto vX;
        cs:
        $D3 = false;
        $RF = new DOMXPath($wm->ownerDocument);
        if (!($this->idNS && is_array($this->idNS))) {
            goto JG;
        }
        foreach ($this->idNS as $og => $HL) {
            $RF->registerNamespace($og, $HL);
            DM:
        }
        dp:
        JG:
        $o5 = "\x40\111\144\75\42" . XPath::filterAttrValue($DY, XPath::DOUBLE_QUOTE) . "\42";
        if (!is_array($this->idKeys)) {
            goto Qu;
        }
        foreach ($this->idKeys as $Uf) {
            $o5 .= "\40\x6f\x72\40\x40" . XPath::filterAttrName($Uf) . "\x3d\42" . XPath::filterAttrValue($DY, XPath::DOUBLE_QUOTE) . "\x22";
            f8:
        }
        SA:
        Qu:
        $BJ = "\57\57\x2a\x5b" . $o5 . "\135";
        $aB = $RF->query($BJ)->item(0);
        vX:
        OS:
        W5:
        $F9 = $this->processTransforms($wm, $aB, $D3);
        if ($this->validateDigest($wm, $F9)) {
            goto e7;
        }
        return false;
        e7:
        if (!$aB instanceof DOMNode) {
            goto xS;
        }
        if (!empty($DY)) {
            goto Kp;
        }
        $this->validatedNodes[] = $aB;
        goto dk;
        Kp:
        $this->validatedNodes[$DY] = $aB;
        dk:
        xS:
        return true;
    }
    public function getRefNodeID($wm)
    {
        if (!($YT = $wm->getAttribute("\125\122\x49"))) {
            goto aq;
        }
        $TN = parse_url($YT);
        if (!empty($TN["\x70\x61\x74\150"])) {
            goto Jw;
        }
        if (!($DY = $TN["\x66\x72\x61\x67\155\145\156\x74"])) {
            goto bi;
        }
        return $DY;
        bi:
        Jw:
        aq:
        return null;
    }
    public function getRefIDs()
    {
        $Z_ = array();
        $Uk = $this->getXPathObj();
        $BJ = "\x2e\57\x73\x65\143\144\163\x69\147\x3a\x53\151\147\x6e\145\x64\111\156\146\157\133\x31\135\x2f\x73\x65\x63\x64\163\151\147\72\x52\145\x66\145\162\x65\x6e\x63\145";
        $jM = $Uk->query($BJ, $this->sigNode);
        if (!($jM->length == 0)) {
            goto kN;
        }
        throw new Exception("\122\145\x66\x65\162\x65\x6e\x63\x65\x20\156\x6f\144\x65\163\x20\x6e\x6f\x74\40\146\x6f\165\x6e\144");
        kN:
        foreach ($jM as $wm) {
            $Z_[] = $this->getRefNodeID($wm);
            Wi:
        }
        ia:
        return $Z_;
    }
    public function validateReference()
    {
        $H0 = $this->sigNode->ownerDocument->documentElement;
        if ($H0->isSameNode($this->sigNode)) {
            goto a3;
        }
        if (!($this->sigNode->parentNode != null)) {
            goto bE;
        }
        $this->sigNode->parentNode->removeChild($this->sigNode);
        bE:
        a3:
        $Uk = $this->getXPathObj();
        $BJ = "\56\x2f\163\145\x63\144\163\151\147\72\x53\x69\x67\x6e\145\144\111\156\x66\x6f\x5b\61\x5d\57\163\x65\x63\x64\163\151\147\x3a\122\145\146\145\162\x65\156\x63\x65";
        $jM = $Uk->query($BJ, $this->sigNode);
        if (!($jM->length == 0)) {
            goto sI;
        }
        throw new Exception("\122\x65\146\x65\x72\145\x6e\143\145\40\x6e\x6f\144\x65\x73\40\156\x6f\x74\x20\146\x6f\x75\156\x64");
        sI:
        $this->validatedNodes = array();
        foreach ($jM as $wm) {
            if ($this->processRefNode($wm)) {
                goto Ma;
            }
            $this->validatedNodes = null;
            throw new Exception("\122\x65\x66\145\x72\x65\x6e\x63\x65\x20\x76\x61\154\151\x64\x61\164\x69\x6f\x6e\x20\x66\x61\151\154\x65\x64");
            Ma:
            VT:
        }
        rs:
        return true;
    }
    private function addRefInternal($vP, $Ci, $af, $H8 = null, $GK = null)
    {
        $sd = null;
        $dF = null;
        $ND = "\x49\x64";
        $yn = true;
        $xo = false;
        if (!is_array($GK)) {
            goto Hw;
        }
        $sd = empty($GK["\x70\162\x65\x66\x69\x78"]) ? null : $GK["\x70\x72\x65\146\x69\x78"];
        $dF = empty($GK["\160\162\x65\146\151\170\137\x6e\163"]) ? null : $GK["\160\162\145\146\151\170\137\x6e\163"];
        $ND = empty($GK["\x69\x64\x5f\156\141\155\x65"]) ? "\x49\x64" : $GK["\151\144\137\x6e\x61\x6d\145"];
        $yn = !isset($GK["\x6f\x76\145\x72\x77\x72\151\164\145"]) ? true : (bool) $GK["\x6f\166\145\x72\x77\162\x69\x74\x65"];
        $xo = !isset($GK["\x66\157\162\143\x65\137\x75\162\151"]) ? false : (bool) $GK["\146\x6f\162\x63\145\x5f\165\x72\151"];
        Hw:
        $yS = $ND;
        if (empty($sd)) {
            goto rV;
        }
        $yS = $sd . "\x3a" . $yS;
        rV:
        $wm = $this->createNewSignNode("\x52\145\146\x65\162\x65\x6e\143\145");
        $vP->appendChild($wm);
        if (!$Ci instanceof DOMDocument) {
            goto ZU;
        }
        if ($xo) {
            goto bd;
        }
        goto Js;
        ZU:
        $YT = null;
        if ($yn) {
            goto q9;
        }
        $YT = $dF ? $Ci->getAttributeNS($dF, $ND) : $Ci->getAttribute($ND);
        q9:
        if (!empty($YT)) {
            goto nH;
        }
        $YT = self::generateGUID();
        $Ci->setAttributeNS($dF, $yS, $YT);
        nH:
        $wm->setAttribute("\125\122\x49", "\x23" . $YT);
        goto Js;
        bd:
        $wm->setAttribute("\x55\122\111", '');
        Js:
        $En = $this->createNewSignNode("\x54\x72\141\x6e\x73\x66\x6f\x72\155\x73");
        $wm->appendChild($En);
        if (is_array($H8)) {
            goto FR;
        }
        if (!empty($this->canonicalMethod)) {
            goto LA;
        }
        goto zW;
        FR:
        foreach ($H8 as $NK) {
            $Qg = $this->createNewSignNode("\124\162\141\156\163\146\157\x72\x6d");
            $En->appendChild($Qg);
            if (is_array($NK) && !empty($NK["\x68\x74\x74\160\x3a\57\x2f\x77\x77\167\x2e\167\x33\56\157\162\147\x2f\x54\122\x2f\x31\x39\71\71\57\x52\x45\103\x2d\170\160\141\x74\150\55\61\x39\x39\x39\x31\61\61\66"]) && !empty($NK["\150\164\x74\x70\72\x2f\57\x77\x77\x77\x2e\167\63\x2e\157\162\147\x2f\124\x52\57\x31\71\x39\71\57\122\105\x43\55\x78\x70\141\164\150\x2d\x31\x39\71\71\61\x31\x31\66"]["\x71\x75\145\162\x79"])) {
                goto uJ;
            }
            $Qg->setAttribute("\101\154\147\157\x72\x69\x74\x68\155", $NK);
            goto jA;
            uJ:
            $Qg->setAttribute("\101\154\147\157\162\151\x74\x68\155", "\x68\x74\x74\160\x3a\x2f\x2f\x77\x77\x77\x2e\167\x33\x2e\x6f\x72\x67\x2f\x54\x52\x2f\61\71\x39\71\x2f\122\x45\x43\55\x78\160\141\x74\x68\x2d\61\71\x39\71\x31\x31\x31\x36");
            $l0 = $this->createNewSignNode("\130\x50\141\164\150", $NK["\x68\x74\164\x70\x3a\57\57\167\x77\x77\56\167\63\56\157\x72\x67\57\124\122\x2f\x31\71\x39\x39\57\x52\105\x43\x2d\170\160\x61\164\150\55\61\x39\x39\71\x31\61\61\66"]["\x71\x75\x65\x72\x79"]);
            $Qg->appendChild($l0);
            if (empty($NK["\150\x74\x74\x70\x3a\57\57\167\167\167\56\167\x33\56\157\162\147\57\x54\122\57\61\x39\x39\71\x2f\x52\x45\103\x2d\170\160\x61\164\x68\55\61\x39\71\x39\x31\61\61\x36"]["\x6e\x61\x6d\x65\163\160\x61\143\x65\163"])) {
                goto wI;
            }
            foreach ($NK["\x68\x74\x74\160\x3a\57\57\167\x77\x77\x2e\x77\x33\x2e\x6f\x72\x67\x2f\124\x52\x2f\x31\x39\x39\71\57\x52\x45\x43\55\170\x70\x61\x74\150\x2d\61\71\71\x39\x31\x31\61\66"]["\x6e\x61\155\145\163\x70\x61\x63\145\163"] as $sd => $qS) {
                $l0->setAttributeNS("\x68\164\x74\160\x3a\57\57\167\167\x77\56\x77\63\56\x6f\x72\147\57\x32\x30\x30\x30\57\x78\x6d\154\156\x73\57", "\x78\155\154\156\x73\72{$sd}", $qS);
                mm:
            }
            Ca:
            wI:
            jA:
            KC:
        }
        v3:
        goto zW;
        LA:
        $Qg = $this->createNewSignNode("\x54\x72\141\x6e\163\x66\157\x72\x6d");
        $En->appendChild($Qg);
        $Qg->setAttribute("\x41\x6c\x67\x6f\x72\x69\164\x68\x6d", $this->canonicalMethod);
        zW:
        $qd = $this->processTransforms($wm, $Ci);
        $CB = $this->calculateDigest($af, $qd);
        $ji = $this->createNewSignNode("\x44\x69\x67\145\163\x74\115\145\x74\x68\157\x64");
        $wm->appendChild($ji);
        $ji->setAttribute("\x41\x6c\147\x6f\x72\151\x74\x68\x6d", $af);
        $PC = $this->createNewSignNode("\104\x69\147\145\x73\x74\126\141\154\165\145", $CB);
        $wm->appendChild($PC);
    }
    public function addReference($Ci, $af, $H8 = null, $GK = null)
    {
        if (!($Uk = $this->getXPathObj())) {
            goto UU;
        }
        $BJ = "\x2e\57\163\145\x63\144\x73\x69\x67\72\x53\151\147\156\x65\144\x49\156\x66\x6f";
        $jM = $Uk->query($BJ, $this->sigNode);
        if (!($j0 = $jM->item(0))) {
            goto jg;
        }
        $this->addRefInternal($j0, $Ci, $af, $H8, $GK);
        jg:
        UU:
    }
    public function addReferenceList($Xa, $af, $H8 = null, $GK = null)
    {
        if (!($Uk = $this->getXPathObj())) {
            goto rQ;
        }
        $BJ = "\56\x2f\163\x65\143\144\163\x69\x67\x3a\x53\x69\147\156\145\x64\x49\x6e\x66\x6f";
        $jM = $Uk->query($BJ, $this->sigNode);
        if (!($j0 = $jM->item(0))) {
            goto PG;
        }
        foreach ($Xa as $Ci) {
            $this->addRefInternal($j0, $Ci, $af, $H8, $GK);
            dV:
        }
        qe:
        PG:
        rQ:
    }
    public function addObject($F9, $yc = null, $vg = null)
    {
        $bz = $this->createNewSignNode("\x4f\x62\152\145\x63\x74");
        $this->sigNode->appendChild($bz);
        if (empty($yc)) {
            goto FG;
        }
        $bz->setAttribute("\x4d\151\x6d\x65\124\x79\160\x65", $yc);
        FG:
        if (empty($vg)) {
            goto Zr;
        }
        $bz->setAttribute("\105\x6e\x63\x6f\x64\x69\156\x67", $vg);
        Zr:
        if ($F9 instanceof DOMElement) {
            goto He;
        }
        $QS = $this->sigNode->ownerDocument->createTextNode($F9);
        goto GT;
        He:
        $QS = $this->sigNode->ownerDocument->importNode($F9, true);
        GT:
        $bz->appendChild($QS);
        return $bz;
    }
    public function locateKey($Ci = null)
    {
        if (!empty($Ci)) {
            goto x0;
        }
        $Ci = $this->sigNode;
        x0:
        if ($Ci instanceof DOMNode) {
            goto Kt;
        }
        return null;
        Kt:
        if (!($NW = $Ci->ownerDocument)) {
            goto Xh;
        }
        $Uk = new DOMXPath($NW);
        $Uk->registerNamespace("\163\x65\143\x64\x73\151\x67", self::XMLDSIGNS);
        $BJ = "\163\x74\x72\151\x6e\x67\x28\56\57\x73\x65\143\144\x73\151\x67\72\123\x69\x67\x6e\x65\144\111\156\x66\157\x2f\163\x65\143\144\x73\151\x67\x3a\123\151\147\x6e\x61\x74\x75\162\145\115\145\x74\x68\157\144\x2f\x40\101\154\147\x6f\x72\x69\x74\150\x6d\51";
        $af = $Uk->evaluate($BJ, $Ci);
        if (!$af) {
            goto zC;
        }
        try {
            $mx = new XMLSecurityKey($af, array("\164\x79\x70\145" => "\x70\165\142\x6c\151\143"));
        } catch (Exception $c4) {
            return null;
        }
        return $mx;
        zC:
        Xh:
        return null;
    }
    public function verify($mx)
    {
        $NW = $this->sigNode->ownerDocument;
        $Uk = new DOMXPath($NW);
        $Uk->registerNamespace("\x73\x65\143\144\x73\x69\147", self::XMLDSIGNS);
        $BJ = "\163\x74\162\151\x6e\x67\x28\56\x2f\x73\x65\x63\x64\x73\x69\x67\x3a\x53\151\147\x6e\141\164\165\x72\x65\x56\x61\154\165\145\x29";
        $xk = $Uk->evaluate($BJ, $this->sigNode);
        if (!empty($xk)) {
            goto ca;
        }
        throw new Exception("\x55\x6e\x61\142\154\x65\40\x74\x6f\40\x6c\x6f\x63\141\x74\x65\x20\123\151\147\156\141\164\x75\x72\145\x56\x61\154\x75\x65");
        ca:
        return $mx->verifySignature($this->signedInfo, base64_decode($xk));
    }
    public function signData($mx, $F9)
    {
        return $mx->signData($F9);
    }
    public function sign($mx, $ft = null)
    {
        if (!($ft != null)) {
            goto pU;
        }
        $this->resetXPathObj();
        $this->appendSignature($ft);
        $this->sigNode = $ft->lastChild;
        pU:
        if (!($Uk = $this->getXPathObj())) {
            goto XM;
        }
        $BJ = "\x2e\57\x73\145\143\x64\163\x69\x67\72\123\151\147\156\145\144\111\156\146\x6f";
        $jM = $Uk->query($BJ, $this->sigNode);
        if (!($j0 = $jM->item(0))) {
            goto WU;
        }
        $BJ = "\56\57\x73\x65\143\x64\163\x69\147\x3a\123\151\147\x6e\x61\x74\165\162\x65\115\x65\164\x68\157\x64";
        $jM = $Uk->query($BJ, $j0);
        $sr = $jM->item(0);
        $sr->setAttribute("\x41\154\x67\x6f\162\x69\x74\150\155", $mx->type);
        $F9 = $this->canonicalizeData($j0, $this->canonicalMethod);
        $xk = base64_encode($this->signData($mx, $F9));
        $ig = $this->createNewSignNode("\x53\151\x67\x6e\x61\x74\x75\x72\145\126\141\154\x75\145", $xk);
        if ($sy = $j0->nextSibling) {
            goto Tz;
        }
        $this->sigNode->appendChild($ig);
        goto rM;
        Tz:
        $sy->parentNode->insertBefore($ig, $sy);
        rM:
        WU:
        XM:
    }
    public function appendCert()
    {
    }
    public function appendKey($mx, $rM = null)
    {
        $mx->serializeKey($rM);
    }
    public function insertSignature($Ci, $N1 = null)
    {
        $ph = $Ci->ownerDocument;
        $IO = $ph->importNode($this->sigNode, true);
        if ($N1 == null) {
            goto PQ;
        }
        return $Ci->insertBefore($IO, $N1);
        goto zp;
        PQ:
        return $Ci->insertBefore($IO);
        zp:
    }
    public function appendSignature($rC, $tM = false)
    {
        $N1 = $tM ? $rC->firstChild : null;
        return $this->insertSignature($rC, $N1);
    }
    public static function get509XCert($N_, $e4 = true)
    {
        $Lm = self::staticGet509XCerts($N_, $e4);
        if (empty($Lm)) {
            goto bp;
        }
        return $Lm[0];
        bp:
        return '';
    }
    public static function staticGet509XCerts($Lm, $e4 = true)
    {
        if ($e4) {
            goto bY;
        }
        return array($Lm);
        goto uG;
        bY:
        $F9 = '';
        $g_ = array();
        $cQ = explode("\xa", $Lm);
        $f_ = false;
        foreach ($cQ as $i7) {
            if (!$f_) {
                goto a6;
            }
            if (!(strncmp($i7, "\x2d\x2d\x2d\55\x2d\x45\x4e\x44\x20\103\x45\x52\124\x49\x46\111\x43\101\124\105", 20) == 0)) {
                goto A7;
            }
            $f_ = false;
            $g_[] = $F9;
            $F9 = '';
            goto U2;
            A7:
            $F9 .= trim($i7);
            goto Lb;
            a6:
            if (!(strncmp($i7, "\55\55\55\55\x2d\x42\105\x47\x49\116\x20\x43\x45\x52\124\111\106\x49\x43\101\x54\105", 22) == 0)) {
                goto H0;
            }
            $f_ = true;
            H0:
            Lb:
            U2:
        }
        am:
        return $g_;
        uG:
    }
    public static function staticAdd509Cert($G7, $N_, $e4 = true, $W0 = false, $Uk = null, $GK = null)
    {
        if (!$W0) {
            goto bv;
        }
        $N_ = file_get_contents($N_);
        bv:
        if ($G7 instanceof DOMElement) {
            goto XA;
        }
        throw new Exception("\x49\156\x76\x61\154\x69\x64\40\x70\141\x72\145\156\x74\x20\116\x6f\x64\145\40\x70\141\162\141\155\x65\164\145\162");
        XA:
        $Jr = $G7->ownerDocument;
        if (!empty($Uk)) {
            goto I_;
        }
        $Uk = new DOMXPath($G7->ownerDocument);
        $Uk->registerNamespace("\x73\x65\x63\144\x73\x69\x67", self::XMLDSIGNS);
        I_:
        $BJ = "\x2e\x2f\x73\x65\143\x64\163\151\147\x3a\x4b\145\x79\111\x6e\146\157";
        $jM = $Uk->query($BJ, $G7);
        $Yj = $jM->item(0);
        $bu = '';
        if (!$Yj) {
            goto k1;
        }
        $UZ = $Yj->lookupPrefix(self::XMLDSIGNS);
        if (empty($UZ)) {
            goto qj;
        }
        $bu = $UZ . "\x3a";
        qj:
        goto KU;
        k1:
        $UZ = $G7->lookupPrefix(self::XMLDSIGNS);
        if (empty($UZ)) {
            goto Zn;
        }
        $bu = $UZ . "\x3a";
        Zn:
        $X3 = false;
        $Yj = $Jr->createElementNS(self::XMLDSIGNS, $bu . "\113\x65\171\x49\x6e\x66\x6f");
        $BJ = "\x2e\57\x73\145\143\x64\x73\151\x67\72\117\142\152\145\143\x74";
        $jM = $Uk->query($BJ, $G7);
        if (!($JH = $jM->item(0))) {
            goto Wb;
        }
        $JH->parentNode->insertBefore($Yj, $JH);
        $X3 = true;
        Wb:
        if ($X3) {
            goto NH;
        }
        $G7->appendChild($Yj);
        NH:
        KU:
        $Lm = self::staticGet509XCerts($N_, $e4);
        $QH = $Jr->createElementNS(self::XMLDSIGNS, $bu . "\x58\65\x30\x39\x44\141\164\141");
        $Yj->appendChild($QH);
        $q1 = false;
        $Wd = false;
        if (!is_array($GK)) {
            goto CY;
        }
        if (empty($GK["\151\163\x73\x75\x65\x72\123\145\x72\x69\x61\154"])) {
            goto Yn;
        }
        $q1 = true;
        Yn:
        if (empty($GK["\163\x75\142\x6a\145\x63\164\116\x61\155\x65"])) {
            goto CR;
        }
        $Wd = true;
        CR:
        CY:
        foreach ($Lm as $TE) {
            if (!($q1 || $Wd)) {
                goto tO;
            }
            if (!($T8 = openssl_x509_parse("\55\x2d\x2d\55\55\102\x45\107\x49\116\x20\103\x45\122\124\x49\x46\x49\103\x41\124\x45\55\x2d\x2d\x2d\55\xa" . chunk_split($TE, 64, "\12") . "\x2d\55\55\55\55\x45\x4e\x44\x20\103\105\x52\124\x49\x46\x49\103\101\x54\x45\x2d\55\55\x2d\55\12"))) {
                goto UK;
            }
            if (!($Wd && !empty($T8["\163\165\142\152\x65\x63\x74"]))) {
                goto yr;
            }
            if (is_array($T8["\x73\165\142\152\145\x63\x74"])) {
                goto z2;
            }
            $mD = $T8["\151\x73\x73\165\x65\162"];
            goto Wa;
            z2:
            $ug = array();
            foreach ($T8["\163\165\142\x6a\145\x63\x74"] as $yQ => $Ox) {
                if (is_array($Ox)) {
                    goto zM;
                }
                array_unshift($ug, "{$yQ}\75{$Ox}");
                goto AK;
                zM:
                foreach ($Ox as $pP) {
                    array_unshift($ug, "{$yQ}\75{$pP}");
                    Qw:
                }
                eL:
                AK:
                iu:
            }
            HA:
            $mD = implode("\54", $ug);
            Wa:
            $gZ = $Jr->createElementNS(self::XMLDSIGNS, $bu . "\x58\x35\60\71\x53\165\142\x6a\145\143\164\116\x61\155\145", $mD);
            $QH->appendChild($gZ);
            yr:
            if (!($q1 && !empty($T8["\151\x73\x73\165\x65\x72"]) && !empty($T8["\x73\145\162\151\141\x6c\x4e\x75\155\142\x65\x72"]))) {
                goto Ij;
            }
            if (is_array($T8["\x69\163\163\x75\145\162"])) {
                goto rY;
            }
            $hy = $T8["\151\x73\163\165\x65\162"];
            goto yH;
            rY:
            $ug = array();
            foreach ($T8["\151\163\163\x75\145\x72"] as $yQ => $Ox) {
                array_unshift($ug, "{$yQ}\x3d{$Ox}");
                vQ:
            }
            Qh:
            $hy = implode("\54", $ug);
            yH:
            $bE = $Jr->createElementNS(self::XMLDSIGNS, $bu . "\130\x35\60\71\x49\163\x73\165\145\x72\x53\x65\162\x69\141\x6c");
            $QH->appendChild($bE);
            $cx = $Jr->createElementNS(self::XMLDSIGNS, $bu . "\130\x35\60\71\x49\x73\163\x75\x65\162\x4e\x61\x6d\145", $hy);
            $bE->appendChild($cx);
            $cx = $Jr->createElementNS(self::XMLDSIGNS, $bu . "\x58\65\x30\x39\x53\x65\x72\151\x61\x6c\x4e\165\x6d\x62\145\x72", $T8["\163\x65\x72\151\141\x6c\x4e\x75\x6d\x62\145\162"]);
            $bE->appendChild($cx);
            Ij:
            UK:
            tO:
            $r_ = $Jr->createElementNS(self::XMLDSIGNS, $bu . "\130\x35\x30\x39\103\x65\x72\x74\x69\146\151\143\141\x74\145", $TE);
            $QH->appendChild($r_);
            pG:
        }
        gq:
    }
    public function add509Cert($N_, $e4 = true, $W0 = false, $GK = null)
    {
        if (!($Uk = $this->getXPathObj())) {
            goto Oa;
        }
        self::staticAdd509Cert($this->sigNode, $N_, $e4, $W0, $Uk, $GK);
        Oa:
    }
    public function appendToKeyInfo($Ci)
    {
        $G7 = $this->sigNode;
        $Jr = $G7->ownerDocument;
        $Uk = $this->getXPathObj();
        if (!empty($Uk)) {
            goto le;
        }
        $Uk = new DOMXPath($G7->ownerDocument);
        $Uk->registerNamespace("\x73\x65\143\x64\163\x69\x67", self::XMLDSIGNS);
        le:
        $BJ = "\x2e\57\163\145\143\144\163\x69\147\72\113\145\171\x49\156\146\157";
        $jM = $Uk->query($BJ, $G7);
        $Yj = $jM->item(0);
        if ($Yj) {
            goto vp;
        }
        $bu = '';
        $UZ = $G7->lookupPrefix(self::XMLDSIGNS);
        if (empty($UZ)) {
            goto af;
        }
        $bu = $UZ . "\72";
        af:
        $X3 = false;
        $Yj = $Jr->createElementNS(self::XMLDSIGNS, $bu . "\x4b\x65\x79\111\x6e\146\x6f");
        $BJ = "\x2e\x2f\163\145\x63\x64\163\x69\147\72\x4f\x62\x6a\145\143\164";
        $jM = $Uk->query($BJ, $G7);
        if (!($JH = $jM->item(0))) {
            goto uo;
        }
        $JH->parentNode->insertBefore($Yj, $JH);
        $X3 = true;
        uo:
        if ($X3) {
            goto kE;
        }
        $G7->appendChild($Yj);
        kE:
        vp:
        $Yj->appendChild($Ci);
        return $Yj;
    }
    public function getValidatedNodes()
    {
        return $this->validatedNodes;
    }
}
