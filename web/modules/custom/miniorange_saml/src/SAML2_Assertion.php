<?php


namespace Drupal\miniorange_saml;

use DOMElement;
use DOMText;
use Exception;
class SAML2_Assertion
{
    private $id;
    private $issueInstant;
    private $issuer;
    private $nameId;
    private $encryptedNameId;
    private $encryptedAttribute;
    private $encryptionKey;
    private $notBefore;
    private $notOnOrAfter;
    private $validAudiences;
    private $sessionNotOnOrAfter;
    private $sessionIndex;
    private $authnInstant;
    private $authnContextClassRef;
    private $authnContextDecl;
    private $authnContextDeclRef;
    private $AuthenticatingAuthority;
    private $attributes;
    private $nameFormat;
    private $signatureKey;
    private $certificates;
    private $signatureData;
    private $requiredEncAttributes;
    private $SubjectConfirmation;
    protected $wasSignedAtConstruction = FALSE;
    public function __construct(DOMElement $mk = NULL)
    {
        $this->id = Utilities::generateId();
        $this->issueInstant = Utilities::generateTimestamp();
        $this->issuer = '';
        $this->authnInstant = Utilities::generateTimestamp();
        $this->attributes = array();
        $this->nameFormat = "\165\162\156\72\x6f\x61\163\x69\x73\72\156\141\155\x65\x73\72\x74\x63\72\123\101\x4d\x4c\x3a\x31\56\61\x3a\x6e\x61\x6d\145\151\144\x2d\x66\x6f\162\x6d\x61\164\x3a\165\156\x73\x70\145\x63\x69\x66\151\145\144";
        $this->certificates = array();
        $this->AuthenticatingAuthority = array();
        $this->SubjectConfirmation = array();
        if (!($mk === NULL)) {
            goto sm;
        }
        return;
        sm:
        if (!($mk->localName === "\105\x6e\x63\162\171\x70\x74\x65\x64\x41\163\x73\x65\x72\164\151\157\x6e")) {
            goto dj;
        }
        $F9 = Utilities::xpQuery($mk, "\56\57\170\145\156\x63\x3a\x45\x6e\143\162\171\160\164\x65\144\104\141\x74\141");
        $Jh = Utilities::xpQuery($mk, "\x2e\57\170\x65\x6e\143\x3a\105\156\x63\x72\171\160\x74\145\x64\104\141\164\141\57\144\163\72\113\145\x79\111\x6e\146\157\x2f\x78\145\x6e\x63\x3a\x45\156\x63\162\x79\160\164\x65\x64\x4b\x65\171");
        $gm = '';
        if (empty($Jh)) {
            goto wE;
        }
        $gm = $Jh[0]->firstChild->getAttribute("\x41\154\147\x6f\x72\x69\x74\150\x6d");
        goto D8;
        wE:
        $Jh = Utilities::xpQuery($mk, "\56\57\x78\x65\x6e\143\x3a\x45\156\x63\x72\x79\x70\164\145\144\113\x65\x79\57\170\145\156\x63\72\x45\156\143\162\171\160\164\151\x6f\156\x4d\145\164\x68\157\144");
        $gm = $Jh[0]->getAttribute("\101\154\147\x6f\162\x69\x74\150\155");
        D8:
        $GC = Utilities::getEncryptionAlgorithm($gm);
        if (count($F9) === 0) {
            goto DN;
        }
        if (count($F9) > 1) {
            goto d3;
        }
        goto FM;
        DN:
        throw new Exception("\x4d\x69\163\163\151\x6e\147\x20\x65\x6e\x63\162\x79\160\x74\145\144\x20\144\141\164\x61\40\151\x6e\x20\74\163\x61\x6d\x6c\x3a\x45\x6e\x63\162\171\160\164\145\144\101\x73\163\145\x72\x74\151\157\156\x3e\56");
        goto FM;
        d3:
        throw new Exception("\115\157\162\145\x20\x74\x68\141\156\40\157\156\145\40\145\x6e\143\162\x79\160\164\x65\144\40\144\141\164\x61\40\145\x6c\145\155\x65\156\x74\40\x69\x6e\40\x3c\163\x61\155\154\72\105\156\143\162\x79\x70\164\145\144\x41\163\x73\x65\162\x74\x69\157\x6e\x3e\56");
        FM:
        $xA = \Drupal::config("\x6d\151\x6e\x69\157\x72\x61\156\x67\x65\x5f\163\x61\x6d\x6c\x2e\163\x65\164\164\151\156\x67\163")->get("\x6d\151\x6e\x69\157\162\x61\x6e\x67\145\137\163\x61\x6d\154\x5f\x70\162\x69\166\x61\164\145\x5f\x63\x65\162\x74\151\146\x69\x63\x61\x74\x65");
        $yQ = new XMLSecurityKey($GC, array("\164\171\x70\x65" => "\x70\162\x69\166\141\164\145"));
        $fB = !is_null($xA) && !empty($xA) ? $xA : MiniorangeSAMLConstants::MINIORANGE_PRIVATE_KEY;
        $yQ->loadKey($fB, FALSE);
        $ce = array();
        $mk = Utilities::decryptElement($F9[0], $yQ, $ce);
        dj:
        if ($mk->hasAttribute("\x49\104")) {
            goto fT;
        }
        throw new Exception("\x4d\151\x73\163\151\156\x67\x20\111\104\40\141\164\x74\162\151\142\x75\x74\x65\x20\157\x6e\x20\123\x41\115\x4c\40\141\x73\163\145\x72\164\x69\x6f\156\x2e");
        fT:
        $this->id = $mk->getAttribute("\111\104");
        if (!($mk->getAttribute("\x56\x65\x72\x73\x69\x6f\x6e") !== "\x32\56\x30")) {
            goto MX;
        }
        throw new Exception("\x55\156\x73\x75\160\x70\157\162\164\145\144\40\166\145\x72\x73\151\x6f\x6e\72\x20" . $mk->getAttribute("\126\x65\162\x73\151\x6f\156"));
        MX:
        $this->issueInstant = Utilities::xsDateTimeToTimestamp($mk->getAttribute("\x49\x73\x73\165\145\111\156\x73\164\x61\156\x74"));
        $Ot = Utilities::xpQuery($mk, "\x2e\x2f\163\x61\x6d\x6c\x5f\141\163\x73\145\162\x74\151\x6f\156\x3a\x49\163\163\x75\145\x72");
        if (!empty($Ot)) {
            goto Ao;
        }
        throw new Exception("\x4d\x69\x73\x73\x69\156\x67\x20\x3c\163\x61\155\154\x3a\x49\163\163\165\145\162\76\40\151\156\x20\x61\x73\x73\145\162\164\x69\157\x6e\56");
        Ao:
        $this->issuer = trim($Ot[0]->textContent);
        $this->parseConditions($mk);
        $this->parseAuthnStatement($mk);
        $this->parseAttributes($mk);
        $this->parseEncryptedAttributes($mk);
        $this->parseSignature($mk);
        $this->parseSubject($mk);
    }
    private function parseSubject(DOMElement $mk)
    {
        $b6 = Utilities::xpQuery($mk, "\56\x2f\x73\x61\155\x6c\x5f\x61\x73\163\x65\x72\x74\x69\x6f\x6e\x3a\123\x75\142\152\x65\143\164");
        if (empty($b6)) {
            goto V4;
        }
        if (count($b6) > 1) {
            goto Hu;
        }
        goto Ag;
        V4:
        return;
        goto Ag;
        Hu:
        throw new Exception("\115\157\162\x65\40\164\x68\x61\x6e\x20\x6f\x6e\145\x20\x3c\163\x61\155\154\72\x53\165\142\x6a\145\x63\164\76\40\151\156\x20\x3c\x73\141\155\x6c\x3a\x41\163\x73\x65\162\164\x69\x6f\156\x3e\56");
        Ag:
        $b6 = $b6[0];
        $Sj = Utilities::xpQuery($b6, "\x2e\57\163\141\x6d\x6c\x5f\141\163\163\145\x72\164\x69\157\156\72\116\x61\155\x65\111\104\40\174\x20\x2e\57\163\141\x6d\154\137\x61\x73\x73\x65\x72\164\151\157\156\x3a\105\156\x63\162\x79\160\x74\145\144\x49\x44\x2f\170\145\x6e\x63\x3a\x45\x6e\143\162\x79\160\x74\x65\x64\x44\x61\x74\x61");
        if (empty($Sj)) {
            goto Dk;
        }
        if (count($Sj) > 1) {
            goto mJ;
        }
        goto NO;
        Dk:
        throw new Exception("\115\151\x73\163\x69\156\147\x20\74\163\141\155\154\x3a\x4e\x61\x6d\x65\x49\x44\76\40\157\x72\x20\x3c\x73\141\155\154\x3a\105\156\x63\162\171\x70\x74\145\144\x49\104\76\x20\151\156\x20\x3c\163\141\155\154\x3a\123\x75\142\152\x65\143\x74\76\56");
        goto NO;
        mJ:
        throw new Exception("\115\157\162\145\x20\164\x68\x61\156\40\x6f\x6e\x65\x20\74\163\141\155\x6c\x3a\116\141\155\145\111\104\76\40\157\162\x20\74\x73\x61\155\x6c\72\x45\156\x63\162\171\160\x74\x65\144\x44\76\40\x69\156\x20\74\x73\141\x6d\x6c\x3a\123\165\142\152\145\143\164\x3e\56");
        NO:
        $Sj = $Sj[0];
        if ($Sj->localName === "\x45\x6e\x63\x72\171\160\x74\145\x64\104\x61\164\x61") {
            goto ha;
        }
        $this->nameId = Utilities::parseNameId($Sj);
        goto f6;
        ha:
        $this->encryptedNameId = $Sj;
        f6:
    }
    private function parseConditions(DOMElement $mk)
    {
        $aZ = Utilities::xpQuery($mk, "\x2e\57\x73\x61\x6d\154\137\141\x73\163\x65\x72\164\x69\x6f\156\72\x43\157\156\x64\x69\x74\x69\157\156\163");
        if (empty($aZ)) {
            goto pI;
        }
        if (count($aZ) > 1) {
            goto HN;
        }
        goto bM;
        pI:
        return;
        goto bM;
        HN:
        throw new Exception("\x4d\157\162\x65\x20\164\x68\141\156\x20\x6f\x6e\145\x20\74\163\141\155\154\x3a\x43\x6f\x6e\144\151\x74\151\157\x6e\x73\x3e\40\x69\x6e\x20\74\163\x61\155\x6c\72\x41\x73\163\145\x72\164\x69\157\156\x3e\56");
        bM:
        $aZ = $aZ[0];
        if (!$aZ->hasAttribute("\116\157\x74\102\x65\x66\157\162\x65")) {
            goto Rs;
        }
        $rb = Utilities::xsDateTimeToTimestamp($aZ->getAttribute("\x4e\157\x74\102\x65\x66\157\x72\145"));
        if (!($this->notBefore === NULL || $this->notBefore < $rb)) {
            goto On;
        }
        $this->notBefore = $rb;
        On:
        Rs:
        if (!$aZ->hasAttribute("\116\157\x74\x4f\x6e\x4f\162\x41\146\164\x65\162")) {
            goto ZW;
        }
        $Xg = Utilities::xsDateTimeToTimestamp($aZ->getAttribute("\116\157\164\x4f\156\x4f\162\101\x66\x74\x65\x72"));
        if (!($this->notOnOrAfter === NULL || $this->notOnOrAfter > $Xg)) {
            goto Ge;
        }
        $this->notOnOrAfter = $Xg;
        Ge:
        ZW:
        $Ci = $aZ->firstChild;
        gG:
        if (!($Ci !== NULL)) {
            goto A9;
        }
        if (!$Ci instanceof DOMText) {
            goto DE;
        }
        goto Uc;
        DE:
        if (!($Ci->namespaceURI !== "\165\162\x6e\x3a\x6f\141\163\151\163\x3a\156\x61\x6d\145\163\72\164\x63\72\x53\x41\x4d\114\72\x32\x2e\60\x3a\x61\x73\163\145\162\164\151\x6f\x6e")) {
            goto Zq;
        }
        throw new Exception("\125\x6e\153\x6e\x6f\x77\156\x20\156\141\155\x65\x73\x70\141\x63\145\x20\157\146\x20\x63\157\x6e\144\x69\164\151\x6f\156\x3a\x20" . var_export($Ci->namespaceURI, TRUE));
        Zq:
        switch ($Ci->localName) {
            case "\101\165\144\151\145\x6e\143\145\122\145\x73\164\x72\x69\143\164\151\157\156":
                $az = Utilities::extractStrings($Ci, "\165\x72\156\72\x6f\141\x73\x69\163\72\x6e\141\x6d\x65\163\x3a\x74\x63\x3a\x53\101\x4d\x4c\72\x32\56\x30\x3a\x61\x73\163\x65\162\164\x69\157\156", "\x41\x75\x64\x69\145\x6e\143\145");
                if ($this->validAudiences === NULL) {
                    goto YI;
                }
                $this->validAudiences = array_intersect($this->validAudiences, $az);
                goto FW;
                YI:
                $this->validAudiences = $az;
                FW:
                goto DL;
            case "\x4f\156\145\124\151\155\x65\125\x73\x65":
                goto DL;
            case "\x50\x72\x6f\170\x79\x52\145\163\164\x72\x69\143\x74\x69\x6f\x6e":
                goto DL;
            default:
                throw new Exception("\125\x6e\x6b\156\157\167\156\40\x63\x6f\x6e\x64\151\x74\151\157\x6e\x3a\40" . var_export($Ci->localName, TRUE));
        }
        yF:
        DL:
        Uc:
        $Ci = $Ci->nextSibling;
        goto gG;
        A9:
    }
    private function parseAuthnStatement(DOMElement $mk)
    {
        $o4 = Utilities::xpQuery($mk, "\56\x2f\x73\x61\155\x6c\137\x61\163\163\145\x72\x74\151\157\156\x3a\x41\x75\x74\150\x6e\123\164\141\164\145\155\x65\156\164");
        if (empty($o4)) {
            goto ln;
        }
        if (count($o4) > 1) {
            goto D2;
        }
        goto Bf;
        ln:
        $this->authnInstant = NULL;
        return;
        goto Bf;
        D2:
        throw new Exception("\115\x6f\162\x65\40\x74\150\x61\164\x20\x6f\x6e\145\40\74\163\x61\x6d\154\x3a\101\165\x74\150\156\123\x74\141\164\145\155\145\156\164\x3e\40\x69\156\40\74\x73\141\155\x6c\x3a\x41\163\163\145\162\164\x69\x6f\156\x3e\x20\x6e\x6f\164\x20\163\165\160\160\x6f\x72\x74\145\144\x2e");
        Bf:
        $fk = $o4[0];
        if ($fk->hasAttribute("\x41\x75\164\150\156\x49\156\163\x74\141\156\x74")) {
            goto ky;
        }
        throw new Exception("\115\151\163\163\151\156\x67\x20\162\145\161\165\151\x72\x65\x64\40\101\165\164\150\156\x49\156\163\x74\x61\x6e\x74\x20\141\164\x74\162\151\x62\165\x74\145\x20\157\x6e\40\74\x73\141\155\154\x3a\x41\x75\164\150\156\x53\164\141\164\145\x6d\x65\156\164\x3e\56");
        ky:
        $this->authnInstant = Utilities::xsDateTimeToTimestamp($fk->getAttribute("\x41\x75\x74\150\156\x49\156\x73\x74\x61\x6e\x74"));
        if (!$fk->hasAttribute("\123\145\163\163\x69\157\x6e\x4e\x6f\164\117\156\117\x72\101\146\164\145\x72")) {
            goto Xw;
        }
        $this->sessionNotOnOrAfter = Utilities::xsDateTimeToTimestamp($fk->getAttribute("\x53\x65\x73\x73\x69\157\x6e\x4e\157\164\117\156\117\x72\101\146\164\145\162"));
        Xw:
        if (!$fk->hasAttribute("\x53\145\163\x73\x69\157\x6e\111\156\x64\145\x78")) {
            goto lO;
        }
        $this->sessionIndex = $fk->getAttribute("\123\x65\x73\x73\x69\x6f\x6e\x49\x6e\x64\145\x78");
        lO:
        $this->parseAuthnContext($fk);
    }
    private function parseAuthnContext(DOMElement $T4)
    {
        $jY = Utilities::xpQuery($T4, "\x2e\x2f\x73\141\155\154\x5f\141\x73\163\145\162\164\151\x6f\x6e\72\x41\165\164\x68\156\103\x6f\x6e\164\x65\170\x74");
        if (count($jY) > 1) {
            goto up;
        }
        if (empty($jY)) {
            goto Q8;
        }
        goto kp;
        up:
        throw new Exception("\x4d\x6f\162\x65\x20\x74\150\x61\156\x20\x6f\156\x65\40\74\x73\x61\x6d\154\x3a\101\165\164\x68\x6e\x43\x6f\156\x74\x65\170\x74\76\x20\151\x6e\x20\74\x73\141\x6d\154\72\101\x75\x74\150\x6e\x53\x74\141\x74\x65\x6d\145\156\164\76\x2e");
        goto kp;
        Q8:
        throw new Exception("\115\x69\163\x73\151\156\x67\40\x72\x65\x71\165\x69\x72\145\144\40\74\x73\x61\x6d\x6c\72\101\165\x74\150\156\x43\x6f\x6e\164\x65\170\x74\76\40\x69\x6e\x20\x3c\163\141\x6d\x6c\72\101\x75\164\150\156\123\x74\141\164\x65\x6d\145\x6e\x74\76\56");
        kp:
        $VX = $jY[0];
        $Ua = Utilities::xpQuery($VX, "\x2e\x2f\x73\141\x6d\x6c\137\141\x73\x73\145\x72\x74\151\x6f\156\x3a\x41\165\x74\150\x6e\x43\157\x6e\164\145\x78\164\x44\145\x63\x6c\x52\x65\x66");
        if (count($Ua) > 1) {
            goto IT;
        }
        if (count($Ua) === 1) {
            goto iv;
        }
        goto bW;
        IT:
        throw new Exception("\115\157\162\x65\40\x74\x68\x61\x6e\x20\x6f\156\x65\40\74\x73\x61\x6d\x6c\x3a\x41\x75\x74\x68\156\x43\x6f\x6e\x74\x65\170\x74\x44\145\143\x6c\122\145\x66\x3e\40\146\x6f\165\x6e\144\77");
        goto bW;
        iv:
        $this->setAuthnContextDeclRef(trim($Ua[0]->textContent));
        bW:
        $e7 = Utilities::xpQuery($VX, "\x2e\x2f\x73\141\x6d\x6c\x5f\141\163\x73\145\x72\x74\151\157\x6e\x3a\x41\x75\x74\150\156\103\157\x6e\x74\x65\x78\x74\104\x65\143\x6c");
        if (count($e7) > 1) {
            goto Hy;
        }
        if (count($e7) === 1) {
            goto XD;
        }
        goto Ft;
        Hy:
        throw new Exception("\115\157\x72\145\40\164\x68\x61\x6e\x20\157\x6e\145\x20\74\x73\x61\155\x6c\72\101\x75\164\150\x6e\x43\x6f\x6e\164\145\170\x74\x44\x65\x63\x6c\x3e\40\146\x6f\165\x6e\x64\x3f");
        goto Ft;
        XD:
        $this->setAuthnContextDecl(new SAML2_XML_Chunk($e7[0]));
        Ft:
        $bf = Utilities::xpQuery($VX, "\x2e\x2f\x73\141\155\x6c\137\141\163\163\145\162\x74\151\157\x6e\x3a\101\x75\164\150\x6e\x43\157\x6e\164\x65\170\x74\103\x6c\x61\163\163\x52\145\x66");
        if (count($bf) > 1) {
            goto WZ;
        }
        if (count($bf) === 1) {
            goto bX;
        }
        goto Wf;
        WZ:
        throw new Exception("\115\157\162\145\x20\x74\150\141\x6e\x20\x6f\156\145\x20\x3c\x73\141\155\x6c\72\101\x75\x74\x68\156\103\157\156\x74\145\x78\164\x43\x6c\141\163\x73\122\145\x66\76\40\151\x6e\40\74\x73\141\x6d\x6c\x3a\101\x75\164\150\x6e\103\x6f\156\164\145\x78\164\x3e\x2e");
        goto Wf;
        bX:
        $this->setAuthnContextClassRef(trim($bf[0]->textContent));
        Wf:
        if (!(empty($this->authnContextClassRef) && empty($this->authnContextDecl) && empty($this->authnContextDeclRef))) {
            goto uL;
        }
        throw new Exception("\x4d\151\163\x73\151\156\147\x20\x65\151\x74\150\145\162\x20\x3c\x73\x61\x6d\154\72\x41\165\164\x68\x6e\x43\x6f\x6e\164\x65\170\x74\x43\154\141\x73\x73\122\x65\x66\76\40\157\162\40\74\163\x61\x6d\154\72\x41\x75\x74\150\156\x43\x6f\156\164\145\170\x74\104\145\143\x6c\122\x65\x66\x3e\x20\x6f\162\40\x3c\163\x61\x6d\154\72\x41\165\164\150\156\103\157\156\x74\x65\170\164\x44\x65\143\154\76");
        uL:
        $this->AuthenticatingAuthority = Utilities::extractStrings($VX, "\x75\162\x6e\72\x6f\141\x73\151\x73\72\x6e\x61\x6d\145\x73\x3a\x74\143\x3a\x53\101\115\114\x3a\62\56\x30\72\141\x73\163\x65\162\x74\x69\157\x6e", "\101\x75\x74\150\145\156\164\x69\x63\x61\164\151\x6e\x67\101\x75\164\x68\x6f\x72\x69\x74\x79");
    }
    private function parseAttributes(DOMElement $mk)
    {
        $mi = TRUE;
        $Nt = Utilities::xpQuery($mk, "\x2e\x2f\163\141\x6d\x6c\x5f\x61\x73\163\x65\x72\x74\151\x6f\156\72\101\164\164\x72\151\142\165\164\145\x53\164\x61\x74\145\155\x65\x6e\164\57\x73\141\x6d\154\x5f\x61\163\163\x65\162\x74\x69\157\156\72\x41\x74\164\x72\x69\142\165\x74\145");
        foreach ($Nt as $PK) {
            if ($PK->hasAttribute("\116\x61\x6d\x65")) {
                goto eT;
            }
            throw new Exception("\115\x69\163\163\151\x6e\147\x20\x6e\141\x6d\145\x20\x6f\x6e\40\x3c\x73\141\x6d\x6c\72\x41\164\164\162\151\x62\x75\164\145\x3e\x20\x65\154\145\x6d\x65\x6e\164\56");
            eT:
            $KC = $PK->getAttribute("\116\141\155\x65");
            if ($PK->hasAttribute("\x4e\x61\x6d\145\x46\157\x72\x6d\141\x74")) {
                goto Zt;
            }
            $F2 = "\x75\x72\x6e\72\x6f\141\163\151\x73\72\156\x61\155\145\x73\72\x74\x63\x3a\x53\x41\x4d\114\72\x31\56\61\x3a\156\x61\x6d\145\151\x64\55\146\157\x72\x6d\141\x74\x3a\165\156\163\160\x65\x63\151\x66\151\145\x64";
            goto lj;
            Zt:
            $F2 = $PK->getAttribute("\x4e\x61\x6d\x65\106\157\x72\155\141\164");
            lj:
            if ($mi) {
                goto Y2;
            }
            if (!($this->nameFormat !== $F2)) {
                goto Bo;
            }
            $this->nameFormat = "\165\x72\x6e\x3a\x6f\141\x73\x69\x73\72\156\x61\x6d\x65\163\72\164\x63\72\x53\101\x4d\114\72\x31\x2e\61\x3a\x6e\141\x6d\x65\151\x64\55\x66\x6f\x72\x6d\x61\x74\72\165\x6e\163\x70\145\x63\151\146\x69\x65\144";
            Bo:
            goto yo;
            Y2:
            $this->nameFormat = $F2;
            $mi = FALSE;
            yo:
            if (array_key_exists($KC, $this->attributes)) {
                goto q8;
            }
            $this->attributes[$KC] = array();
            q8:
            $tk = Utilities::xpQuery($PK, "\56\57\x73\x61\x6d\154\137\x61\x73\163\x65\162\x74\151\x6f\x6e\72\x41\164\164\162\x69\142\165\164\145\126\141\154\165\145");
            foreach ($tk as $Ox) {
                $this->attributes[$KC][] = trim($Ox->textContent);
                fE:
            }
            et:
            zb:
        }
        iG:
    }
    private function parseEncryptedAttributes(DOMElement $mk)
    {
        $this->encryptedAttribute = Utilities::xpQuery($mk, "\56\57\x73\x61\x6d\154\137\x61\163\163\145\162\x74\x69\x6f\x6e\72\x41\x74\x74\x72\151\x62\165\x74\145\x53\x74\x61\x74\145\x6d\x65\156\164\57\163\x61\x6d\154\137\141\x73\x73\x65\x72\x74\x69\157\x6e\x3a\105\156\143\x72\x79\160\x74\145\144\x41\x74\x74\x72\x69\142\165\164\x65");
    }
    private function parseSignature(DOMElement $mk)
    {
        $kk = Utilities::validateElement($mk);
        if (!($kk !== FALSE)) {
            goto ek;
        }
        $this->wasSignedAtConstruction = TRUE;
        $this->certificates = $kk["\x43\x65\x72\164\151\x66\x69\143\141\164\x65\163"];
        $this->signatureData = $kk;
        ek:
    }
    public function validate(XMLSecurityKey $yQ)
    {
        if (!($this->signatureData === NULL)) {
            goto AJ;
        }
        return FALSE;
        AJ:
        Utilities::validateSignature($this->signatureData, $yQ);
        return TRUE;
    }
    public function getId()
    {
        return $this->id;
    }
    public function setId($MF)
    {
        $this->id = $MF;
    }
    public function getIssueInstant()
    {
        return $this->issueInstant;
    }
    public function setIssueInstant($OU)
    {
        $this->issueInstant = $OU;
    }
    public function getIssuer()
    {
        return $this->issuer;
    }
    public function setIssuer($Ot)
    {
        $this->issuer = $Ot;
    }
    public function getNameId()
    {
        if (!($this->encryptedNameId !== NULL)) {
            goto W6;
        }
        throw new Exception("\101\x74\164\145\x6d\x70\164\x65\x64\40\x74\157\40\162\145\x74\x72\x69\x65\x76\145\40\145\x6e\x63\162\171\160\x74\145\x64\40\116\x61\155\x65\x49\x44\40\x77\151\x74\x68\x6f\165\164\40\144\145\143\162\171\x70\164\151\x6e\147\40\151\x74\x20\146\x69\x72\x73\164\56");
        W6:
        return $this->nameId;
    }
    public function setNameId($Sj)
    {
        $this->nameId = $Sj;
    }
    public function isNameIdEncrypted()
    {
        if (!($this->encryptedNameId !== NULL)) {
            goto G2;
        }
        return TRUE;
        G2:
        return FALSE;
    }
    public function encryptNameId(XMLSecurityKey $yQ)
    {
        $NW = new DOMDocument();
        $wp = $NW->createElement("\162\x6f\x6f\164");
        $NW->appendChild($wp);
        Utilities::addNameId($wp, $this->nameId);
        $Sj = $wp->firstChild;
        Utilities::getContainer()->debugMessage($Sj, "\145\x6e\x63\x72\x79\160\164");
        $en = new XMLSecEnc();
        $en->setNode($Sj);
        $en->type = XMLSecEnc::Element;
        $sw = new XMLSecurityKey(XMLSecurityKey::AES128_CBC);
        $sw->generateSessionKey();
        $en->encryptKey($yQ, $sw);
        $this->encryptedNameId = $en->encryptNode($sw);
        $this->nameId = NULL;
    }
    public function decryptNameId(XMLSecurityKey $yQ, array $ce = array())
    {
        if (!($this->encryptedNameId === NULL)) {
            goto CE;
        }
        return;
        CE:
        $Sj = Utilities::decryptElement($this->encryptedNameId, $yQ, $ce);
        Utilities::getContainer()->debugMessage($Sj, "\x64\145\143\x72\171\x70\164");
        $this->nameId = Utilities::parseNameId($Sj);
        $this->encryptedNameId = NULL;
    }
    public function decryptAttributes(XMLSecurityKey $yQ, array $ce = array())
    {
        if (!($this->encryptedAttribute === NULL)) {
            goto sZ;
        }
        return;
        sZ:
        $mi = TRUE;
        $Nt = $this->encryptedAttribute;
        foreach ($Nt as $QZ) {
            $PK = Utilities::decryptElement($QZ->getElementsByTagName("\x45\x6e\143\x72\171\160\164\x65\x64\x44\141\x74\x61")->item(0), $yQ, $ce);
            if ($PK->hasAttribute("\x4e\x61\155\x65")) {
                goto VP;
            }
            throw new Exception("\115\x69\x73\163\151\x6e\x67\40\x6e\141\155\x65\40\157\156\40\74\x73\141\155\x6c\72\101\164\x74\x72\151\142\x75\x74\145\x3e\x20\x65\x6c\x65\x6d\145\x6e\x74\56");
            VP:
            $KC = $PK->getAttribute("\116\x61\155\145");
            if ($PK->hasAttribute("\x4e\141\155\145\x46\x6f\162\x6d\141\164")) {
                goto Th;
            }
            $F2 = "\x75\x72\156\x3a\157\x61\163\151\163\x3a\156\x61\x6d\145\163\72\164\x63\x3a\x53\x41\115\114\72\x32\x2e\x30\x3a\x61\x74\x74\162\x6e\x61\155\145\x2d\x66\157\x72\x6d\x61\x74\x3a\x75\x6e\163\x70\x65\x63\x69\x66\x69\145\144";
            goto NR;
            Th:
            $F2 = $PK->getAttribute("\x4e\x61\155\x65\106\x6f\x72\155\x61\x74");
            NR:
            if ($mi) {
                goto sr;
            }
            if (!($this->nameFormat !== $F2)) {
                goto kv;
            }
            $this->nameFormat = "\165\x72\156\72\x6f\x61\x73\x69\x73\x3a\156\141\155\x65\163\x3a\x74\x63\x3a\x53\101\x4d\x4c\x3a\62\56\60\72\x61\x74\164\x72\x6e\x61\155\145\x2d\x66\x6f\162\155\141\x74\72\165\x6e\163\160\x65\x63\151\x66\x69\x65\144";
            kv:
            goto SF;
            sr:
            $this->nameFormat = $F2;
            $mi = FALSE;
            SF:
            if (array_key_exists($KC, $this->attributes)) {
                goto BX;
            }
            $this->attributes[$KC] = array();
            BX:
            $tk = Utilities::xpQuery($PK, "\56\x2f\163\141\155\x6c\137\x61\x73\x73\145\x72\164\151\x6f\156\72\101\x74\164\162\x69\142\x75\164\145\126\x61\x6c\x75\145");
            foreach ($tk as $Ox) {
                $this->attributes[$KC][] = trim($Ox->textContent);
                Ac:
            }
            GS:
            i0:
        }
        mM:
    }
    public function getNotBefore()
    {
        return $this->notBefore;
    }
    public function setNotBefore($rb)
    {
        $this->notBefore = $rb;
    }
    public function getNotOnOrAfter()
    {
        return $this->notOnOrAfter;
    }
    public function setNotOnOrAfter($Xg)
    {
        $this->notOnOrAfter = $Xg;
    }
    public function setEncryptedAttributes($Vz)
    {
        $this->requiredEncAttributes = $Vz;
    }
    public function getValidAudiences()
    {
        return $this->validAudiences;
    }
    public function setValidAudiences(array $eO = NULL)
    {
        $this->validAudiences = $eO;
    }
    public function getAuthnInstant()
    {
        return $this->authnInstant;
    }
    public function setAuthnInstant($UX)
    {
        $this->authnInstant = $UX;
    }
    public function getSessionNotOnOrAfter()
    {
        return $this->sessionNotOnOrAfter;
    }
    public function setSessionNotOnOrAfter($z4)
    {
        $this->sessionNotOnOrAfter = $z4;
    }
    public function getSessionIndex()
    {
        return $this->sessionIndex;
    }
    public function setSessionIndex($mT)
    {
        $this->sessionIndex = $mT;
    }
    public function getAuthnContext()
    {
        if (empty($this->authnContextClassRef)) {
            goto iK;
        }
        return $this->authnContextClassRef;
        iK:
        if (empty($this->authnContextDeclRef)) {
            goto H4;
        }
        return $this->authnContextDeclRef;
        H4:
        return NULL;
    }
    public function setAuthnContext($WM)
    {
        $this->setAuthnContextClassRef($WM);
    }
    public function getAuthnContextClassRef()
    {
        return $this->authnContextClassRef;
    }
    public function setAuthnContextClassRef($fG)
    {
        $this->authnContextClassRef = $fG;
    }
    public function setAuthnContextDecl(SAML2_XML_Chunk $B9)
    {
        if (empty($this->authnContextDeclRef)) {
            goto cw;
        }
        throw new Exception("\101\x75\x74\150\156\103\157\156\x74\x65\x78\164\104\x65\143\154\122\145\x66\x20\151\x73\40\141\154\x72\145\x61\x64\171\40\162\145\x67\151\163\x74\x65\x72\x65\x64\41\40\115\x61\x79\40\157\x6e\154\171\x20\x68\x61\x76\x65\40\x65\151\x74\150\145\x72\40\141\x20\104\145\143\x6c\x20\157\162\x20\x61\40\x44\145\143\154\x52\x65\146\x2c\x20\156\157\x74\x20\x62\157\x74\x68\41");
        cw:
        $this->authnContextDecl = $B9;
    }
    public function getAuthnContextDecl()
    {
        return $this->authnContextDecl;
    }
    public function setAuthnContextDeclRef($e9)
    {
        if (empty($this->authnContextDecl)) {
            goto Ak;
        }
        throw new Exception("\x41\165\x74\x68\x6e\x43\157\156\x74\145\x78\164\104\145\x63\154\40\x69\163\x20\x61\154\x72\145\141\x64\x79\40\x72\145\x67\x69\x73\x74\145\x72\145\144\41\40\x4d\x61\171\x20\x6f\156\x6c\171\x20\x68\x61\x76\145\x20\x65\x69\164\x68\145\x72\x20\x61\x20\104\145\x63\x6c\x20\157\x72\x20\x61\x20\104\145\x63\154\122\x65\x66\x2c\x20\x6e\x6f\164\40\142\157\164\150\41");
        Ak:
        $this->authnContextDeclRef = $e9;
    }
    public function getAuthnContextDeclRef()
    {
        return $this->authnContextDeclRef;
    }
    public function getAuthenticatingAuthority()
    {
        return $this->AuthenticatingAuthority;
    }
    public function setAuthenticatingAuthority($dt)
    {
        $this->AuthenticatingAuthority = $dt;
    }
    public function getAttributes()
    {
        return $this->attributes;
    }
    public function setAttributes(array $Nt)
    {
        $this->attributes = $Nt;
    }
    public function getAttributeNameFormat()
    {
        return $this->nameFormat;
    }
    public function setAttributeNameFormat($F2)
    {
        $this->nameFormat = $F2;
    }
    public function getSubjectConfirmation()
    {
        return $this->SubjectConfirmation;
    }
    public function setSubjectConfirmation(array $U0)
    {
        $this->SubjectConfirmation = $U0;
    }
    public function getSignatureKey()
    {
        return $this->signatureKey;
    }
    public function getSignatureData()
    {
        return $this->signatureData;
    }
    public function setSignatureKey(XMLsecurityKey $Rg = NULL)
    {
        $this->signatureKey = $Rg;
    }
    public function getEncryptionKey()
    {
        return $this->encryptionKey;
    }
    public function setEncryptionKey(XMLSecurityKey $eD = NULL)
    {
        $this->encryptionKey = $eD;
    }
    public function setCertificates(array $Tx)
    {
        $this->certificates = $Tx;
    }
    public function getCertificates()
    {
        return $this->certificates;
    }
    public function getWasSignedAtConstruction()
    {
        return $this->wasSignedAtConstruction;
    }
    public function toXML(DOMNode $Kq = NULL)
    {
        if ($Kq === NULL) {
            goto Jq;
        }
        $ph = $Kq->ownerDocument;
        goto g1;
        Jq:
        $ph = new DOMDocument();
        $Kq = $ph;
        g1:
        $wp = $ph->createElementNS("\165\x72\156\x3a\x6f\x61\x73\x69\x73\x3a\156\x61\x6d\145\163\72\164\143\x3a\x53\x41\x4d\114\x3a\x32\56\60\x3a\141\x73\x73\145\162\164\151\157\x6e", "\163\x61\x6d\x6c\72" . "\x41\163\163\x65\x72\x74\151\157\156");
        $Kq->appendChild($wp);
        $wp->setAttributeNS("\x75\162\156\72\157\x61\163\x69\x73\72\156\141\x6d\145\163\72\x74\x63\72\123\x41\115\114\x3a\62\x2e\x30\x3a\160\x72\x6f\164\157\x63\x6f\x6c", "\163\141\x6d\154\x70\x3a\x74\x6d\160", "\164\x6d\160");
        $wp->removeAttributeNS("\165\162\x6e\72\157\141\163\x69\163\x3a\156\x61\155\x65\163\72\x74\143\x3a\x53\x41\115\x4c\72\x32\56\x30\x3a\160\x72\157\x74\x6f\x63\x6f\154", "\164\x6d\160");
        $wp->setAttributeNS("\x68\x74\x74\x70\x3a\57\x2f\167\167\x77\x2e\167\63\56\x6f\x72\x67\x2f\62\x30\60\61\x2f\130\x4d\x4c\x53\x63\150\145\155\141\55\151\x6e\163\x74\x61\x6e\x63\x65", "\x78\163\x69\72\x74\x6d\x70", "\164\155\x70");
        $wp->removeAttributeNS("\x68\x74\x74\x70\x3a\57\x2f\x77\167\x77\x2e\167\63\56\157\x72\x67\x2f\62\x30\x30\61\x2f\x58\x4d\114\123\x63\x68\x65\x6d\x61\55\x69\x6e\x73\164\141\x6e\143\x65", "\x74\155\160");
        $wp->setAttributeNS("\150\x74\164\x70\72\x2f\x2f\167\167\167\56\x77\63\x2e\157\162\x67\57\x32\x30\60\x31\x2f\130\x4d\x4c\x53\x63\150\x65\155\141", "\x78\x73\x3a\x74\x6d\x70", "\x74\155\160");
        $wp->removeAttributeNS("\150\x74\164\x70\72\x2f\57\x77\167\167\x2e\x77\x33\56\x6f\162\x67\x2f\62\x30\60\61\57\130\x4d\114\123\143\x68\145\x6d\141", "\164\155\x70");
        $wp->setAttribute("\x49\104", $this->id);
        $wp->setAttribute("\x56\x65\162\163\151\x6f\x6e", "\62\x2e\x30");
        $wp->setAttribute("\x49\163\x73\x75\x65\111\156\163\x74\x61\x6e\164", gmdate("\x59\55\155\55\144\x5c\x54\110\72\x69\72\163\x5c\132", $this->issueInstant));
        $Ot = Utilities::addString($wp, "\x75\x72\x6e\x3a\157\141\163\151\x73\72\x6e\141\x6d\x65\163\72\164\x63\72\x53\x41\x4d\114\72\x32\x2e\x30\x3a\141\x73\x73\145\x72\164\x69\157\x6e", "\163\141\155\x6c\x3a\x49\163\x73\x75\145\x72", $this->issuer);
        $this->addSubject($wp);
        $this->addConditions($wp);
        $this->addAuthnStatement($wp);
        if ($this->requiredEncAttributes == FALSE) {
            goto eG;
        }
        $this->addEncryptedAttributeStatement($wp);
        goto J6;
        eG:
        $this->addAttributeStatement($wp);
        J6:
        if (!($this->signatureKey !== NULL)) {
            goto ZZ;
        }
        Utilities::insertSignature($this->signatureKey, $this->certificates, $wp, $Ot->nextSibling);
        ZZ:
        return $wp;
    }
    private function addSubject(DOMElement $wp)
    {
        if (!($this->nameId === NULL && $this->encryptedNameId === NULL)) {
            goto B9;
        }
        return;
        B9:
        $b6 = $wp->ownerDocument->createElementNS("\x75\x72\156\x3a\x6f\141\x73\151\163\72\156\141\x6d\145\163\x3a\164\143\x3a\x53\101\x4d\114\72\x32\x2e\60\x3a\x61\163\163\145\x72\164\151\x6f\156", "\163\x61\x6d\154\x3a\123\165\x62\x6a\145\143\x74");
        $wp->appendChild($b6);
        if ($this->encryptedNameId === NULL) {
            goto u3;
        }
        $KA = $b6->ownerDocument->createElementNS("\165\162\156\x3a\x6f\x61\163\x69\x73\x3a\156\x61\155\145\x73\72\164\x63\x3a\123\x41\x4d\x4c\72\x32\x2e\x30\72\x61\163\163\x65\162\164\x69\157\x6e", "\163\141\x6d\154\x3a" . "\105\156\x63\162\171\160\x74\145\x64\x49\x44");
        $b6->appendChild($KA);
        $KA->appendChild($b6->ownerDocument->importNode($this->encryptedNameId, TRUE));
        goto ow;
        u3:
        Utilities::addNameId($b6, $this->nameId);
        ow:
        foreach ($this->SubjectConfirmation as $JG) {
            $JG->toXML($b6);
            dG:
        }
        kw:
    }
    private function addConditions(DOMElement $wp)
    {
        $ph = $wp->ownerDocument;
        $aZ = $ph->createElementNS("\x75\x72\156\x3a\157\x61\x73\x69\163\72\156\x61\x6d\x65\163\72\x74\143\x3a\123\101\x4d\x4c\72\62\56\x30\72\x61\163\x73\145\162\x74\151\x6f\156", "\163\141\x6d\x6c\x3a\x43\x6f\x6e\144\151\x74\151\x6f\x6e\163");
        $wp->appendChild($aZ);
        if (!($this->notBefore !== NULL)) {
            goto zX;
        }
        $aZ->setAttribute("\116\157\x74\x42\x65\146\157\162\x65", gmdate("\131\55\x6d\55\x64\x5c\x54\x48\x3a\151\72\x73\134\132", $this->notBefore));
        zX:
        if (!($this->notOnOrAfter !== NULL)) {
            goto zV;
        }
        $aZ->setAttribute("\x4e\157\164\x4f\156\117\x72\101\x66\164\145\x72", gmdate("\131\55\x6d\x2d\144\134\x54\110\72\x69\72\x73\x5c\x5a", $this->notOnOrAfter));
        zV:
        if (!($this->validAudiences !== NULL)) {
            goto f9;
        }
        $oc = $ph->createElementNS("\x75\162\156\72\x6f\x61\x73\151\x73\72\x6e\x61\x6d\x65\163\72\164\143\72\123\101\115\x4c\72\62\x2e\x30\72\x61\163\163\145\162\164\x69\x6f\x6e", "\x73\x61\x6d\x6c\72\101\165\x64\151\145\156\143\x65\x52\145\x73\x74\x72\151\143\x74\151\x6f\x6e");
        $aZ->appendChild($oc);
        Utilities::addStrings($oc, "\165\x72\x6e\x3a\x6f\141\x73\x69\x73\x3a\x6e\x61\x6d\145\163\x3a\164\x63\72\123\101\115\x4c\x3a\x32\x2e\60\x3a\x61\x73\x73\x65\x72\164\151\x6f\x6e", "\163\x61\155\154\x3a\x41\x75\x64\151\145\156\x63\145", FALSE, $this->validAudiences);
        f9:
    }
    private function addAuthnStatement(DOMElement $wp)
    {
        if (!($this->authnInstant === NULL || $this->authnContextClassRef === NULL && $this->authnContextDecl === NULL && $this->authnContextDeclRef === NULL)) {
            goto Jo;
        }
        return;
        Jo:
        $ph = $wp->ownerDocument;
        $T4 = $ph->createElementNS("\165\162\156\72\157\141\163\x69\163\72\156\141\x6d\x65\163\x3a\164\x63\72\123\x41\115\114\72\62\x2e\x30\x3a\x61\163\163\145\x72\164\151\x6f\156", "\163\x61\x6d\x6c\72\x41\x75\164\x68\156\123\164\141\164\145\x6d\x65\156\x74");
        $wp->appendChild($T4);
        $T4->setAttribute("\x41\x75\164\x68\x6e\111\156\163\x74\141\x6e\x74", gmdate("\x59\55\155\x2d\x64\x5c\124\110\72\x69\72\163\x5c\132", $this->authnInstant));
        if (!($this->sessionNotOnOrAfter !== NULL)) {
            goto En;
        }
        $T4->setAttribute("\123\145\x73\x73\x69\x6f\x6e\116\157\164\x4f\156\x4f\x72\x41\x66\164\145\x72", gmdate("\x59\x2d\155\x2d\144\x5c\x54\x48\72\151\x3a\163\x5c\x5a", $this->sessionNotOnOrAfter));
        En:
        if (!($this->sessionIndex !== NULL)) {
            goto La;
        }
        $T4->setAttribute("\123\x65\163\x73\151\157\x6e\111\156\x64\145\170", $this->sessionIndex);
        La:
        $VX = $ph->createElementNS("\165\162\156\x3a\157\141\x73\x69\163\x3a\x6e\x61\155\145\163\x3a\x74\x63\72\123\101\x4d\x4c\72\62\x2e\x30\x3a\x61\x73\x73\x65\162\164\x69\157\x6e", "\x73\141\x6d\154\72\101\x75\x74\150\156\x43\x6f\156\164\145\170\164");
        $T4->appendChild($VX);
        if (empty($this->authnContextClassRef)) {
            goto pY;
        }
        Utilities::addString($VX, "\x75\162\156\72\157\141\163\x69\x73\x3a\156\141\x6d\x65\x73\x3a\x74\143\72\x53\101\x4d\114\72\x32\56\60\72\141\163\x73\145\162\164\151\x6f\156", "\x73\141\x6d\154\72\x41\x75\x74\150\x6e\x43\x6f\x6e\164\x65\x78\x74\x43\154\141\x73\x73\x52\x65\146", $this->authnContextClassRef);
        pY:
        if (empty($this->authnContextDecl)) {
            goto HZ;
        }
        $this->authnContextDecl->toXML($VX);
        HZ:
        if (empty($this->authnContextDeclRef)) {
            goto xo;
        }
        Utilities::addString($VX, "\x75\162\x6e\72\x6f\141\163\151\x73\72\x6e\x61\155\145\x73\72\x74\143\x3a\123\101\x4d\114\x3a\62\x2e\x30\72\141\163\163\x65\x72\x74\151\x6f\156", "\163\141\155\x6c\72\101\165\164\x68\x6e\x43\x6f\x6e\164\x65\170\164\x44\145\143\154\x52\145\146", $this->authnContextDeclRef);
        xo:
        Utilities::addStrings($VX, "\x75\162\x6e\72\157\x61\163\x69\x73\72\x6e\x61\155\x65\163\x3a\x74\143\x3a\x53\x41\115\x4c\72\62\56\x30\x3a\141\163\x73\145\162\x74\151\157\x6e", "\163\x61\155\x6c\x3a\x41\x75\164\x68\x65\156\x74\151\x63\141\164\x69\156\x67\x41\x75\164\x68\157\162\x69\164\171", FALSE, $this->AuthenticatingAuthority);
    }
    private function addAttributeStatement(DOMElement $wp)
    {
        if (!empty($this->attributes)) {
            goto ot;
        }
        return;
        ot:
        $ph = $wp->ownerDocument;
        $k1 = $ph->createElementNS("\165\x72\x6e\72\157\x61\x73\x69\163\x3a\156\141\155\x65\x73\x3a\164\143\72\123\x41\115\x4c\72\x32\56\60\72\141\163\x73\x65\x72\x74\151\x6f\x6e", "\163\141\155\154\72\101\x74\x74\162\x69\x62\x75\x74\145\x53\164\x61\164\145\155\x65\x6e\x74");
        $wp->appendChild($k1);
        foreach ($this->attributes as $KC => $tk) {
            $PK = $ph->createElementNS("\165\x72\x6e\72\157\141\x73\x69\x73\72\x6e\141\x6d\x65\x73\72\164\143\72\123\101\115\x4c\x3a\x32\56\60\72\141\163\x73\x65\162\164\151\157\156", "\163\141\x6d\154\x3a\x41\164\164\x72\151\142\x75\x74\145");
            $k1->appendChild($PK);
            $PK->setAttribute("\x4e\141\x6d\x65", $KC);
            if (!($this->nameFormat !== "\x75\162\x6e\x3a\157\141\x73\x69\163\72\156\x61\155\145\163\x3a\x74\143\x3a\123\x41\115\x4c\x3a\62\56\x30\x3a\x61\x74\164\162\156\141\155\145\55\x66\x6f\x72\155\141\x74\x3a\x75\x6e\x73\160\x65\x63\151\x66\x69\x65\x64")) {
                goto dN;
            }
            $PK->setAttribute("\x4e\x61\x6d\x65\106\157\x72\x6d\141\164", $this->nameFormat);
            dN:
            foreach ($tk as $Ox) {
                if (is_string($Ox)) {
                    goto dc;
                }
                if (is_int($Ox)) {
                    goto Qq;
                }
                $O_ = NULL;
                goto Op;
                dc:
                $O_ = "\170\163\x3a\163\164\x72\x69\x6e\x67";
                goto Op;
                Qq:
                $O_ = "\x78\163\x3a\151\156\x74\145\147\x65\162";
                Op:
                $Za = $ph->createElementNS("\165\x72\x6e\72\x6f\x61\163\151\163\72\156\141\155\145\163\x3a\164\143\72\x53\101\x4d\114\x3a\62\56\x30\72\x61\163\163\145\x72\x74\x69\157\x6e", "\163\x61\x6d\154\72\x41\x74\x74\x72\151\142\x75\x74\x65\126\141\x6c\x75\145");
                $PK->appendChild($Za);
                if (!($O_ !== NULL)) {
                    goto i1;
                }
                $Za->setAttributeNS("\150\x74\x74\x70\x3a\x2f\57\x77\167\x77\56\x77\63\56\157\x72\147\x2f\x32\x30\60\61\57\130\x4d\x4c\123\143\150\145\x6d\x61\55\x69\x6e\163\x74\141\156\x63\x65", "\170\163\x69\72\x74\x79\x70\x65", $O_);
                i1:
                if (!is_null($Ox)) {
                    goto cH;
                }
                $Za->setAttributeNS("\x68\x74\x74\160\x3a\x2f\57\x77\x77\x77\56\167\63\x2e\157\162\x67\x2f\62\x30\x30\61\57\x58\115\x4c\x53\143\150\145\x6d\141\55\x69\x6e\x73\164\141\156\143\x65", "\170\x73\x69\72\156\151\x6c", "\x74\x72\x75\145");
                cH:
                if ($Ox instanceof DOMNodeList) {
                    goto ej;
                }
                $Za->appendChild($ph->createTextNode($Ox));
                goto hC;
                ej:
                $vk = 0;
                SZ:
                if (!($vk < $Ox->length)) {
                    goto VY;
                }
                $Ci = $ph->importNode($Ox->item($vk), TRUE);
                $Za->appendChild($Ci);
                Aj:
                $vk++;
                goto SZ;
                VY:
                hC:
                oO:
            }
            ct:
            Gf:
        }
        A5:
    }
    private function addEncryptedAttributeStatement(DOMElement $wp)
    {
        if (!($this->requiredEncAttributes == FALSE)) {
            goto uw;
        }
        return;
        uw:
        $ph = $wp->ownerDocument;
        $k1 = $ph->createElementNS("\x75\162\x6e\x3a\157\x61\163\151\x73\72\x6e\x61\x6d\x65\x73\72\164\x63\x3a\123\101\x4d\114\x3a\62\56\60\72\141\x73\163\x65\162\164\151\x6f\156", "\163\141\155\154\72\101\x74\164\162\151\x62\x75\164\145\123\164\141\164\145\155\x65\x6e\164");
        $wp->appendChild($k1);
        foreach ($this->attributes as $KC => $tk) {
            $xu = new DOMDocument();
            $PK = $xu->createElementNS("\x75\x72\156\x3a\157\141\163\151\163\72\x6e\x61\155\x65\163\x3a\x74\x63\72\123\x41\x4d\114\72\x32\x2e\x30\72\x61\x73\163\x65\162\x74\x69\157\156", "\x73\141\155\154\72\101\164\164\162\x69\x62\165\164\x65");
            $PK->setAttribute("\116\x61\x6d\x65", $KC);
            $xu->appendChild($PK);
            if (!($this->nameFormat !== "\165\162\156\x3a\x6f\141\x73\151\163\x3a\x6e\x61\x6d\145\x73\x3a\x74\143\x3a\x53\x41\115\114\x3a\62\x2e\x30\72\x61\x74\164\x72\156\x61\155\x65\x2d\x66\157\x72\155\x61\x74\72\x75\156\x73\x70\145\x63\x69\146\151\x65\x64")) {
                goto yE;
            }
            $PK->setAttribute("\x4e\141\155\x65\106\157\x72\155\141\x74", $this->nameFormat);
            yE:
            foreach ($tk as $Ox) {
                if (is_string($Ox)) {
                    goto EI;
                }
                if (is_int($Ox)) {
                    goto j5;
                }
                $O_ = NULL;
                goto vo;
                EI:
                $O_ = "\170\163\72\163\x74\x72\x69\156\147";
                goto vo;
                j5:
                $O_ = "\x78\x73\72\151\156\x74\145\x67\x65\x72";
                vo:
                $Za = $xu->createElementNS("\x75\162\x6e\72\157\x61\x73\x69\x73\72\x6e\x61\155\x65\163\72\164\x63\72\123\x41\x4d\x4c\72\62\56\60\x3a\x61\163\x73\x65\162\x74\151\x6f\x6e", "\x73\x61\x6d\154\72\x41\x74\x74\162\x69\x62\165\164\x65\x56\x61\154\x75\x65");
                $PK->appendChild($Za);
                if (!($O_ !== NULL)) {
                    goto IS;
                }
                $Za->setAttributeNS("\x68\x74\164\160\72\x2f\x2f\x77\x77\x77\x2e\x77\x33\x2e\157\x72\147\x2f\62\x30\60\x31\57\x58\115\114\x53\143\150\x65\155\x61\55\151\156\x73\164\x61\x6e\x63\x65", "\x78\x73\x69\72\164\x79\x70\x65", $O_);
                IS:
                if ($Ox instanceof DOMNodeList) {
                    goto Ds;
                }
                $Za->appendChild($xu->createTextNode($Ox));
                goto ry;
                Ds:
                $vk = 0;
                nu:
                if (!($vk < $Ox->length)) {
                    goto yb;
                }
                $Ci = $xu->importNode($Ox->item($vk), TRUE);
                $Za->appendChild($Ci);
                kj:
                $vk++;
                goto nu;
                yb:
                ry:
                C_:
            }
            Hr:
            $z5 = new XMLSecEnc();
            $z5->setNode($xu->documentElement);
            $z5->type = "\150\x74\164\160\x3a\57\57\167\167\167\x2e\x77\x33\x2e\157\x72\x67\57\62\x30\x30\61\57\60\64\x2f\170\155\x6c\145\156\143\43\x45\x6c\145\x6d\x65\156\x74";
            $sw = new XMLSecurityKey(XMLSecurityKey::AES256_CBC);
            $sw->generateSessionKey();
            $z5->encryptKey($this->encryptionKey, $sw);
            $uY = $z5->encryptNode($sw);
            $hk = $ph->createElementNS("\165\162\x6e\x3a\157\141\x73\151\x73\72\156\141\155\145\163\x3a\164\x63\x3a\123\x41\115\114\72\62\56\60\72\x61\163\x73\x65\x72\x74\151\157\156", "\x73\141\x6d\x6c\72\105\156\143\162\171\x70\x74\145\x64\x41\164\x74\162\151\142\x75\164\x65");
            $k1->appendChild($hk);
            $oD = $ph->importNode($uY, TRUE);
            $hk->appendChild($oD);
            Eg:
        }
        eU:
    }
}
