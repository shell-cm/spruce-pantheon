<?php


namespace Drupal\miniorange_saml;

use DOMDocument;
use DOMElement;
use DOMNode;
use DOMXPath;
use Exception;
class XMLSecEnc
{
    const template = "\x3c\170\x65\156\x63\x3a\105\x6e\143\x72\171\160\x74\145\144\x44\x61\x74\141\40\170\155\x6c\x6e\x73\72\170\x65\156\143\75\x27\x68\x74\x74\x70\72\x2f\57\x77\167\x77\56\x77\63\x2e\157\x72\147\x2f\x32\60\60\x31\x2f\x30\x34\x2f\x78\155\154\145\156\x63\x23\47\x3e\12\x20\x20\40\74\170\145\156\143\72\x43\x69\160\x68\145\162\104\141\x74\141\x3e\xa\x20\x20\40\40\x20\40\x3c\170\145\156\x63\x3a\x43\x69\160\150\145\162\x56\x61\x6c\165\145\76\74\x2f\170\145\x6e\x63\72\103\x69\160\150\x65\162\x56\141\x6c\x75\145\x3e\xa\x20\x20\x20\74\57\x78\x65\x6e\143\72\103\151\x70\x68\145\x72\104\141\x74\x61\76\xa\74\x2f\170\x65\x6e\143\x3a\105\x6e\143\x72\171\160\164\x65\144\x44\141\x74\x61\x3e";
    const Element = "\x68\x74\164\160\x3a\x2f\57\167\x77\x77\x2e\167\63\x2e\x6f\162\x67\x2f\62\x30\x30\x31\57\60\x34\x2f\x78\155\154\x65\x6e\143\x23\x45\x6c\x65\x6d\145\156\164";
    const Content = "\150\164\164\x70\x3a\57\57\167\x77\167\x2e\167\63\x2e\157\x72\147\x2f\62\60\x30\61\57\60\x34\57\x78\155\x6c\145\x6e\x63\x23\x43\157\156\164\145\156\164";
    const URI = 3;
    const XMLENCNS = "\150\x74\x74\160\72\x2f\x2f\x77\x77\x77\x2e\167\63\x2e\x6f\x72\x67\57\x32\60\60\x31\x2f\x30\x34\x2f\x78\x6d\x6c\x65\156\143\x23";
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
    public function addReference($KC, $Ci, $O_)
    {
        if ($Ci instanceof DOMNode) {
            goto Ze;
        }
        throw new Exception("\x24\156\157\144\x65\x20\151\163\x20\156\157\x74\x20\157\146\x20\x74\x79\x70\x65\40\x44\x4f\x4d\116\x6f\x64\x65");
        Ze:
        $ab = $this->encdoc;
        $this->_resetTemplate();
        $B4 = $this->encdoc;
        $this->encdoc = $ab;
        $Sc = XMLSecurityDSig::generateGUID();
        $cJ = $B4->documentElement;
        $cJ->setAttribute("\111\144", $Sc);
        $this->references[$KC] = array("\x6e\x6f\x64\x65" => $Ci, "\x74\x79\x70\145" => $O_, "\145\156\x63\156\x6f\x64\145" => $B4, "\162\145\x66\165\x72\x69" => $Sc);
    }
    public function setNode($Ci)
    {
        $this->rawNode = $Ci;
    }
    public function encryptNode($mx, $Oj = true)
    {
        $F9 = '';
        if (!empty($this->rawNode)) {
            goto ZT;
        }
        throw new Exception("\x4e\x6f\x64\145\x20\164\x6f\x20\x65\156\x63\x72\x79\x70\x74\40\x68\x61\x73\40\x6e\x6f\164\x20\x62\x65\145\x6e\40\x73\x65\164");
        ZT:
        if ($mx instanceof XMLSecurityKey) {
            goto I7;
        }
        throw new Exception("\111\x6e\166\141\154\x69\144\40\x4b\x65\x79");
        I7:
        $NW = $this->rawNode->ownerDocument;
        $RF = new DOMXPath($this->encdoc);
        $ay = $RF->query("\x2f\x78\145\156\x63\x3a\105\156\x63\162\171\160\164\145\144\x44\141\164\141\57\x78\145\x6e\143\72\x43\x69\160\150\x65\162\x44\x61\164\x61\57\x78\x65\156\x63\x3a\103\151\x70\x68\145\162\126\x61\154\165\x65");
        $FL = $ay->item(0);
        if (!($FL == null)) {
            goto iA;
        }
        throw new Exception("\x45\x72\x72\x6f\x72\40\x6c\x6f\143\141\x74\x69\x6e\147\x20\103\151\160\150\145\162\x56\x61\154\165\x65\x20\145\154\145\155\x65\156\164\40\x77\x69\164\x68\151\x6e\40\164\145\155\x70\154\141\x74\145");
        iA:
        switch ($this->type) {
            case self::Element:
                $F9 = $NW->saveXML($this->rawNode);
                $this->encdoc->documentElement->setAttribute("\x54\x79\160\145", self::Element);
                goto Gk;
            case self::Content:
                $Hf = $this->rawNode->childNodes;
                foreach ($Hf as $kh) {
                    $F9 .= $NW->saveXML($kh);
                    g6:
                }
                Q6:
                $this->encdoc->documentElement->setAttribute("\x54\171\160\x65", self::Content);
                goto Gk;
            default:
                throw new Exception("\x54\171\160\x65\x20\151\x73\40\x63\165\x72\x72\x65\x6e\x74\154\171\x20\156\157\x74\x20\163\x75\160\x70\157\162\x74\145\x64");
        }
        Nh:
        Gk:
        $w_ = $this->encdoc->documentElement->appendChild($this->encdoc->createElementNS(self::XMLENCNS, "\170\145\x6e\x63\x3a\x45\x6e\143\162\171\160\164\151\157\x6e\x4d\x65\164\x68\x6f\144"));
        $w_->setAttribute("\101\154\x67\157\x72\151\164\150\x6d", $mx->getAlgorithm());
        $FL->parentNode->parentNode->insertBefore($w_, $FL->parentNode->parentNode->firstChild);
        $H9 = base64_encode($mx->encryptData($F9));
        $Ox = $this->encdoc->createTextNode($H9);
        $FL->appendChild($Ox);
        if ($Oj) {
            goto YO;
        }
        return $this->encdoc->documentElement;
        goto gv;
        YO:
        switch ($this->type) {
            case self::Element:
                if (!($this->rawNode->nodeType == XML_DOCUMENT_NODE)) {
                    goto cl;
                }
                return $this->encdoc;
                cl:
                $qi = $this->rawNode->ownerDocument->importNode($this->encdoc->documentElement, true);
                $this->rawNode->parentNode->replaceChild($qi, $this->rawNode);
                return $qi;
            case self::Content:
                $qi = $this->rawNode->ownerDocument->importNode($this->encdoc->documentElement, true);
                qs:
                if (!$this->rawNode->firstChild) {
                    goto Xy;
                }
                $this->rawNode->removeChild($this->rawNode->firstChild);
                goto qs;
                Xy:
                $this->rawNode->appendChild($qi);
                return $qi;
        }
        Qg:
        Zv:
        gv:
    }
    public function encryptReferences($mx)
    {
        $cR = $this->rawNode;
        $im = $this->type;
        foreach ($this->references as $KC => $hK) {
            $this->encdoc = $hK["\145\x6e\x63\x6e\x6f\x64\x65"];
            $this->rawNode = $hK["\156\x6f\x64\x65"];
            $this->type = $hK["\x74\x79\x70\145"];
            try {
                $An = $this->encryptNode($mx);
                $this->references[$KC]["\x65\x6e\143\156\157\x64\x65"] = $An;
            } catch (Exception $c4) {
                $this->rawNode = $cR;
                $this->type = $im;
                throw $c4;
            }
            hh:
        }
        Mz:
        $this->rawNode = $cR;
        $this->type = $im;
    }
    public function getCipherValue()
    {
        if (!empty($this->rawNode)) {
            goto yD;
        }
        throw new Exception("\116\x6f\x64\x65\40\164\x6f\x20\144\x65\x63\162\171\x70\164\x20\150\x61\x73\40\x6e\157\164\x20\142\x65\145\x6e\x20\163\x65\164");
        yD:
        $NW = $this->rawNode->ownerDocument;
        $RF = new DOMXPath($NW);
        $RF->registerNamespace("\170\155\x6c\145\x6e\x63\162", self::XMLENCNS);
        $BJ = "\x2e\57\x78\155\154\x65\x6e\143\x72\72\103\151\160\150\145\162\104\141\164\x61\x2f\x78\x6d\154\x65\x6e\143\162\x3a\103\151\160\150\145\x72\126\141\154\165\x65";
        $jM = $RF->query($BJ, $this->rawNode);
        $Ci = $jM->item(0);
        if ($Ci) {
            goto mt;
        }
        return null;
        mt:
        return base64_decode($Ci->nodeValue);
    }
    public function decryptNode($mx, $Oj = true)
    {
        if ($mx instanceof XMLSecurityKey) {
            goto Rl;
        }
        throw new Exception("\x49\x6e\166\x61\154\x69\x64\40\113\145\x79");
        Rl:
        $I0 = $this->getCipherValue();
        if ($I0) {
            goto wj;
        }
        throw new Exception("\103\141\156\x6e\x6f\164\40\x6c\157\x63\141\x74\x65\40\145\156\143\x72\171\x70\x74\145\x64\40\x64\141\x74\x61");
        goto YX;
        wj:
        $qE = $mx->decryptData($I0);
        if ($Oj) {
            goto Ff;
        }
        return $qE;
        goto BF;
        Ff:
        switch ($this->type) {
            case self::Element:
                $l2 = new DOMDocument();
                $l2->loadXML($qE);
                if (!($this->rawNode->nodeType == XML_DOCUMENT_NODE)) {
                    goto Ii;
                }
                return $l2;
                Ii:
                $qi = $this->rawNode->ownerDocument->importNode($l2->documentElement, true);
                $this->rawNode->parentNode->replaceChild($qi, $this->rawNode);
                return $qi;
            case self::Content:
                if ($this->rawNode->nodeType == XML_DOCUMENT_NODE) {
                    goto hv;
                }
                $NW = $this->rawNode->ownerDocument;
                goto GX;
                hv:
                $NW = $this->rawNode;
                GX:
                $pB = $NW->createDocumentFragment();
                $pB->appendXML($qE);
                $rM = $this->rawNode->parentNode;
                $rM->replaceChild($pB, $this->rawNode);
                return $rM;
            default:
                return $qE;
        }
        E9:
        QT:
        BF:
        YX:
    }
    public function encryptKey($R4, $p2, $J0 = true)
    {
        if (!(!$R4 instanceof XMLSecurityKey || !$p2 instanceof XMLSecurityKey)) {
            goto nt;
        }
        throw new Exception("\x49\x6e\166\x61\154\x69\144\x20\x4b\x65\171");
        nt:
        $ip = base64_encode($R4->encryptData($p2->key));
        $wp = $this->encdoc->documentElement;
        $nC = $this->encdoc->createElementNS(self::XMLENCNS, "\x78\145\156\143\x3a\x45\x6e\143\162\x79\x70\164\145\144\113\x65\x79");
        if ($J0) {
            goto qT;
        }
        $this->encKey = $nC;
        goto g4;
        qT:
        $Yj = $wp->insertBefore($this->encdoc->createElementNS("\x68\x74\x74\160\x3a\57\x2f\x77\x77\x77\56\x77\x33\56\x6f\162\x67\57\62\60\x30\x30\57\60\71\x2f\170\155\x6c\x64\x73\x69\147\x23", "\x64\163\151\147\72\113\145\x79\x49\156\146\157"), $wp->firstChild);
        $Yj->appendChild($nC);
        g4:
        $w_ = $nC->appendChild($this->encdoc->createElementNS(self::XMLENCNS, "\170\145\156\x63\x3a\105\156\143\x72\x79\x70\x74\x69\x6f\x6e\x4d\145\164\150\157\x64"));
        $w_->setAttribute("\101\154\x67\x6f\x72\151\164\x68\155", $R4->getAlgorith());
        if (empty($R4->name)) {
            goto Nd;
        }
        $Yj = $nC->appendChild($this->encdoc->createElementNS("\150\164\164\160\x3a\57\x2f\167\x77\x77\x2e\x77\x33\x2e\157\x72\x67\x2f\62\x30\x30\60\57\x30\71\57\x78\155\154\144\x73\x69\x67\x23", "\x64\163\151\147\x3a\x4b\x65\x79\111\x6e\x66\x6f"));
        $Yj->appendChild($this->encdoc->createElementNS("\x68\164\164\x70\x3a\57\57\167\167\167\x2e\x77\x33\56\157\x72\147\x2f\62\60\x30\x30\x2f\x30\x39\57\x78\x6d\154\x64\x73\151\x67\x23", "\144\163\x69\147\72\113\x65\x79\116\x61\x6d\x65", $R4->name));
        Nd:
        $vC = $nC->appendChild($this->encdoc->createElementNS(self::XMLENCNS, "\170\x65\x6e\143\72\x43\151\160\x68\x65\x72\104\x61\164\x61"));
        $vC->appendChild($this->encdoc->createElementNS(self::XMLENCNS, "\170\145\156\x63\72\x43\151\160\x68\145\x72\x56\141\x6c\x75\145", $ip));
        if (!(is_array($this->references) && count($this->references) > 0)) {
            goto tC;
        }
        $kA = $nC->appendChild($this->encdoc->createElementNS(self::XMLENCNS, "\x78\145\x6e\x63\x3a\122\x65\x66\x65\x72\x65\x6e\143\145\114\151\163\x74"));
        foreach ($this->references as $KC => $hK) {
            $Sc = $hK["\162\145\146\x75\x72\151"];
            $K6 = $kA->appendChild($this->encdoc->createElementNS(self::XMLENCNS, "\170\145\156\x63\x3a\x44\x61\164\x61\122\145\146\x65\162\145\156\143\x65"));
            $K6->setAttribute("\125\x52\111", "\43" . $Sc);
            LW:
        }
        lh:
        tC:
        return;
    }
    public function decryptKey($nC)
    {
        if ($nC->isEncrypted) {
            goto eV;
        }
        throw new Exception("\113\145\x79\x20\x69\x73\40\x6e\x6f\164\x20\x45\156\143\x72\x79\x70\x74\145\144");
        eV:
        if (!empty($nC->key)) {
            goto ko;
        }
        throw new Exception("\x4b\x65\171\x20\x69\x73\x20\155\x69\x73\x73\151\x6e\x67\40\144\141\164\141\x20\164\x6f\x20\160\x65\162\146\x6f\162\x6d\40\x74\x68\145\x20\x64\x65\143\162\x79\x70\x74\x69\x6f\156");
        ko:
        return $this->decryptNode($nC, false);
    }
    public function locateEncryptedData($cJ)
    {
        if ($cJ instanceof DOMDocument) {
            goto NK;
        }
        $NW = $cJ->ownerDocument;
        goto QG;
        NK:
        $NW = $cJ;
        QG:
        if (!$NW) {
            goto Bg;
        }
        $Uk = new DOMXPath($NW);
        $BJ = "\57\x2f\x2a\x5b\154\157\x63\141\x6c\x2d\x6e\x61\155\x65\50\x29\x3d\x27\105\x6e\143\162\171\x70\x74\x65\x64\x44\141\164\141\x27\x20\x61\156\144\x20\156\x61\x6d\x65\x73\160\141\143\145\x2d\x75\x72\151\x28\x29\x3d\x27" . self::XMLENCNS . "\x27\x5d";
        $jM = $Uk->query($BJ);
        return $jM->item(0);
        Bg:
        return null;
    }
    public function locateKey($Ci = null)
    {
        if (!empty($Ci)) {
            goto q6;
        }
        $Ci = $this->rawNode;
        q6:
        if ($Ci instanceof DOMNode) {
            goto HU;
        }
        return null;
        HU:
        if (!($NW = $Ci->ownerDocument)) {
            goto Ja;
        }
        $Uk = new DOMXPath($NW);
        $Uk->registerNamespace("\170\x6d\x6c\x73\x65\x63\145\156\x63", self::XMLENCNS);
        $BJ = "\x2e\x2f\57\170\155\x6c\163\145\143\145\x6e\x63\72\105\x6e\x63\162\171\160\164\x69\x6f\x6e\x4d\145\x74\150\157\x64";
        $jM = $Uk->query($BJ, $Ci);
        if (!($lm = $jM->item(0))) {
            goto cL;
        }
        $Uv = $lm->getAttribute("\x41\x6c\x67\157\x72\x69\164\x68\x6d");
        try {
            $mx = new XMLSecurityKey($Uv, array("\164\x79\x70\145" => "\160\x72\x69\x76\x61\164\145"));
        } catch (Exception $c4) {
            return null;
        }
        return $mx;
        cL:
        Ja:
        return null;
    }
    public static function staticLocateKeyInfo($I6 = null, $Ci = null)
    {
        if (!(empty($Ci) || !$Ci instanceof DOMNode)) {
            goto Dn;
        }
        return null;
        Dn:
        $NW = $Ci->ownerDocument;
        if ($NW) {
            goto Dv;
        }
        return null;
        Dv:
        $Uk = new DOMXPath($NW);
        $Uk->registerNamespace("\x78\x6d\154\163\145\143\x65\156\143", self::XMLENCNS);
        $Uk->registerNamespace("\170\155\x6c\163\145\143\144\163\x69\147", XMLSecurityDSig::XMLDSIGNS);
        $BJ = "\56\57\x78\155\154\163\x65\x63\144\163\x69\x67\x3a\x4b\145\x79\111\x6e\x66\157";
        $jM = $Uk->query($BJ, $Ci);
        $lm = $jM->item(0);
        if ($lm) {
            goto gR;
        }
        return $I6;
        gR:
        foreach ($lm->childNodes as $kh) {
            switch ($kh->localName) {
                case "\x4b\145\x79\x4e\x61\x6d\145":
                    if (empty($I6)) {
                        goto pr;
                    }
                    $I6->name = $kh->nodeValue;
                    pr:
                    goto PJ;
                case "\113\x65\171\x56\x61\x6c\165\x65":
                    foreach ($kh->childNodes as $AX) {
                        switch ($AX->localName) {
                            case "\x44\x53\x41\113\x65\171\x56\141\x6c\165\145":
                                throw new Exception("\104\x53\x41\113\145\171\x56\x61\x6c\165\145\40\x63\165\162\x72\145\x6e\164\154\x79\x20\156\x6f\164\40\163\x75\x70\x70\x6f\162\x74\145\x64");
                            case "\122\123\101\x4b\x65\171\x56\x61\x6c\x75\x65":
                                $G9 = null;
                                $i4 = null;
                                if (!($je = $AX->getElementsByTagName("\115\x6f\144\165\154\165\163")->item(0))) {
                                    goto l_;
                                }
                                $G9 = base64_decode($je->nodeValue);
                                l_:
                                if (!($xZ = $AX->getElementsByTagName("\105\x78\x70\x6f\156\145\x6e\x74")->item(0))) {
                                    goto dy;
                                }
                                $i4 = base64_decode($xZ->nodeValue);
                                dy:
                                if (!(empty($G9) || empty($i4))) {
                                    goto ak;
                                }
                                throw new Exception("\115\151\163\163\151\x6e\147\x20\x4d\157\144\165\x6c\x75\x73\x20\x6f\162\x20\x45\x78\160\157\156\145\156\164");
                                ak:
                                $nQ = XMLSecurityKey::convertRSA($G9, $i4);
                                $I6->loadKey($nQ);
                                goto LX;
                        }
                        Vj:
                        LX:
                        YM:
                    }
                    nE:
                    goto PJ;
                case "\x52\x65\164\x72\151\145\166\x61\154\115\x65\164\x68\157\x64":
                    $O_ = $kh->getAttribute("\x54\x79\x70\145");
                    if (!($O_ !== "\x68\164\164\x70\72\57\x2f\167\x77\x77\56\167\63\x2e\x6f\x72\x67\x2f\x32\60\60\x31\57\60\64\57\x78\x6d\x6c\145\x6e\143\43\105\156\x63\162\171\160\x74\x65\x64\x4b\145\x79")) {
                        goto NF;
                    }
                    goto PJ;
                    NF:
                    $YT = $kh->getAttribute("\125\122\x49");
                    if (!($YT[0] !== "\43")) {
                        goto AV;
                    }
                    goto PJ;
                    AV:
                    $MF = substr($YT, 1);
                    $BJ = "\57\x2f\170\x6d\x6c\x73\145\x63\x65\156\143\x3a\105\156\x63\x72\171\160\164\x65\x64\113\145\x79\x5b\x40\111\x64\75\x22" . XPath::filterAttrValue($MF, XPath::DOUBLE_QUOTE) . "\x22\x5d";
                    $KB = $Uk->query($BJ)->item(0);
                    if ($KB) {
                        goto Mv;
                    }
                    throw new Exception("\125\x6e\141\142\x6c\x65\x20\164\157\40\x6c\157\143\x61\x74\x65\x20\x45\156\143\162\x79\160\x74\x65\x64\x4b\145\x79\40\167\x69\164\150\x20\x40\x49\144\x3d\47{$MF}\x27\56");
                    Mv:
                    return XMLSecurityKey::fromEncryptedKeyElement($KB);
                case "\105\156\143\x72\171\160\164\145\x64\x4b\x65\171":
                    return XMLSecurityKey::fromEncryptedKeyElement($kh);
                case "\130\x35\x30\x39\x44\x61\x74\x61":
                    if (!($DV = $kh->getElementsByTagName("\x58\x35\60\71\103\x65\162\164\x69\146\x69\143\x61\x74\145"))) {
                        goto X3;
                    }
                    if (!($DV->length > 0)) {
                        goto sF;
                    }
                    $LX = $DV->item(0)->textContent;
                    $LX = str_replace(array("\15", "\xa", "\40"), '', $LX);
                    $LX = "\x2d\x2d\x2d\55\55\x42\105\x47\111\116\40\103\105\122\124\111\106\x49\x43\x41\124\105\55\x2d\55\x2d\55\12" . chunk_split($LX, 64, "\xa") . "\55\x2d\55\x2d\x2d\105\116\x44\40\103\x45\122\124\111\x46\111\x43\101\124\105\55\x2d\x2d\55\55\xa";
                    $I6->loadKey($LX, false, true);
                    sF:
                    X3:
                    goto PJ;
            }
            c2:
            PJ:
            Fj:
        }
        y6:
        return $I6;
    }
    public function locateKeyInfo($I6 = null, $Ci = null)
    {
        if (!empty($Ci)) {
            goto jM;
        }
        $Ci = $this->rawNode;
        jM:
        return self::staticLocateKeyInfo($I6, $Ci);
    }
}
