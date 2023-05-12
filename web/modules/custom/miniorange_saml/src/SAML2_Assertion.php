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
    public function __construct(DOMElement $Z0 = NULL)
    {
        $this->id = Utilities::generateId();
        $this->issueInstant = Utilities::generateTimestamp();
        $this->issuer = '';
        $this->authnInstant = Utilities::generateTimestamp();
        $this->attributes = array();
        $this->nameFormat = "\x75\x72\156\x3a\x6f\141\163\x69\163\x3a\x6e\x61\155\x65\163\72\164\x63\72\123\101\115\114\x3a\61\x2e\61\72\x6e\x61\x6d\x65\x69\x64\55\146\x6f\x72\155\141\x74\x3a\165\156\x73\160\145\x63\x69\x66\x69\x65\x64";
        $this->certificates = array();
        $this->AuthenticatingAuthority = array();
        $this->SubjectConfirmation = array();
        if (!($Z0 === NULL)) {
            goto rN;
        }
        return;
        rN:
        if (!($Z0->localName === "\x45\156\x63\x72\x79\x70\x74\x65\x64\101\163\x73\x65\x72\164\151\x6f\156")) {
            goto Kr;
        }
        $LF = Utilities::xpQuery($Z0, "\x2e\x2f\x78\x65\156\143\72\105\x6e\x63\162\171\160\x74\x65\x64\104\x61\x74\x61");
        $U8 = Utilities::xpQuery($Z0, "\x2e\x2f\170\x65\x6e\x63\72\105\156\143\162\171\160\x74\x65\144\104\141\x74\x61\57\x64\x73\x3a\x4b\x65\x79\111\x6e\146\157\x2f\x78\145\x6e\143\72\x45\x6e\143\x72\171\x70\x74\145\144\x4b\x65\x79");
        $XF = '';
        if (empty($U8)) {
            goto jy;
        }
        $XF = $U8[0]->firstChild->getAttribute("\101\x6c\x67\157\162\151\164\x68\155");
        goto oK;
        jy:
        $U8 = Utilities::xpQuery($Z0, "\x2e\x2f\x78\145\x6e\143\x3a\105\x6e\143\162\x79\x70\x74\x65\x64\113\x65\x79\57\x78\x65\156\x63\x3a\105\x6e\143\x72\171\160\x74\151\x6f\156\115\x65\164\x68\157\x64");
        $XF = $U8[0]->getAttribute("\x41\x6c\x67\x6f\162\151\164\150\x6d");
        oK:
        $yY = Utilities::getEncryptionAlgorithm($XF);
        if (count($LF) === 0) {
            goto EI;
        }
        if (count($LF) > 1) {
            goto VG;
        }
        goto gU;
        EI:
        throw new Exception("\115\x69\163\x73\151\x6e\x67\x20\145\156\143\x72\x79\160\164\145\144\40\x64\141\x74\x61\x20\151\156\40\x3c\163\141\155\154\x3a\105\x6e\x63\x72\x79\160\x74\145\144\101\x73\163\x65\162\x74\151\x6f\156\76\56");
        goto gU;
        VG:
        throw new Exception("\x4d\157\162\145\40\x74\150\x61\156\x20\157\x6e\x65\40\x65\x6e\143\162\171\x70\164\x65\144\40\144\x61\164\x61\40\145\154\145\155\x65\156\x74\x20\x69\x6e\x20\74\x73\141\155\x6c\x3a\x45\156\x63\x72\x79\160\164\145\x64\101\163\163\145\x72\x74\151\157\x6e\x3e\x2e");
        gU:
        $Ax = \Drupal::config("\155\x69\156\151\157\162\141\x6e\x67\145\137\x73\x61\x6d\x6c\56\x73\x65\x74\164\151\x6e\x67\x73")->get("\155\151\156\x69\x6f\x72\141\x6e\147\145\x5f\163\141\x6d\x6c\137\x70\162\x69\x76\x61\164\145\x5f\143\x65\162\x74\x69\x66\151\x63\x61\164\145");
        $eQ = new XMLSecurityKey($yY, array("\164\x79\x70\145" => "\x70\x72\x69\166\x61\x74\x65"));
        $Ql = !is_null($Ax) && !empty($Ax) ? $Ax : MiniorangeSAMLConstants::MINIORANGE_PRIVATE_KEY;
        $eQ->loadKey($Ql, FALSE);
        $qo = array();
        $Z0 = Utilities::decryptElement($LF[0], $eQ, $qo);
        Kr:
        if ($Z0->hasAttribute("\x49\104")) {
            goto IL;
        }
        throw new Exception("\115\151\x73\x73\x69\x6e\147\40\111\104\x20\141\164\x74\x72\x69\x62\x75\x74\x65\40\x6f\156\40\x53\x41\x4d\x4c\40\x61\163\x73\145\x72\164\151\x6f\156\56");
        IL:
        $this->id = $Z0->getAttribute("\111\x44");
        if (!($Z0->getAttribute("\126\x65\162\163\151\157\156") !== "\62\56\60")) {
            goto dG;
        }
        throw new Exception("\x55\156\x73\x75\x70\160\157\x72\x74\145\x64\40\166\145\162\x73\x69\157\156\72\40" . $Z0->getAttribute("\x56\x65\x72\x73\151\157\156"));
        dG:
        $this->issueInstant = Utilities::xsDateTimeToTimestamp($Z0->getAttribute("\x49\163\163\x75\145\111\156\x73\x74\141\x6e\164"));
        $YM = Utilities::xpQuery($Z0, "\56\x2f\163\141\155\x6c\137\x61\x73\x73\x65\162\164\x69\157\156\x3a\111\163\x73\x75\145\162");
        if (!empty($YM)) {
            goto ze;
        }
        throw new Exception("\x4d\151\x73\163\151\156\147\40\x3c\x73\141\155\154\72\x49\x73\x73\x75\145\x72\x3e\x20\x69\x6e\x20\x61\x73\x73\x65\x72\164\x69\157\156\56");
        ze:
        $this->issuer = trim($YM[0]->textContent);
        $this->parseConditions($Z0);
        $this->parseAuthnStatement($Z0);
        $this->parseAttributes($Z0);
        $this->parseEncryptedAttributes($Z0);
        $this->parseSignature($Z0);
        $this->parseSubject($Z0);
    }
    private function parseSubject(DOMElement $Z0)
    {
        $gp = Utilities::xpQuery($Z0, "\x2e\x2f\163\x61\155\154\x5f\141\x73\163\145\x72\164\x69\157\156\72\x53\165\142\x6a\145\x63\164");
        if (empty($gp)) {
            goto R6;
        }
        if (count($gp) > 1) {
            goto fi;
        }
        goto Rd;
        R6:
        return;
        goto Rd;
        fi:
        throw new Exception("\x4d\x6f\162\x65\x20\x74\x68\141\x6e\x20\x6f\x6e\145\40\x3c\x73\141\x6d\x6c\72\x53\165\142\x6a\x65\x63\x74\x3e\x20\x69\x6e\x20\74\x73\x61\155\154\72\x41\163\163\145\x72\x74\151\x6f\x6e\x3e\x2e");
        Rd:
        $gp = $gp[0];
        $Pp = Utilities::xpQuery($gp, "\56\x2f\x73\141\155\154\137\x61\x73\x73\x65\x72\164\151\157\x6e\72\x4e\x61\155\145\x49\x44\40\x7c\40\x2e\57\163\141\x6d\x6c\137\x61\163\163\x65\162\164\x69\x6f\156\x3a\x45\156\x63\162\171\x70\x74\x65\x64\x49\104\57\x78\145\156\x63\x3a\105\156\x63\162\x79\160\164\x65\x64\x44\x61\x74\x61");
        if (empty($Pp)) {
            goto ok;
        }
        if (count($Pp) > 1) {
            goto qL;
        }
        goto RW;
        ok:
        throw new Exception("\115\x69\x73\x73\x69\x6e\147\x20\74\x73\x61\155\154\72\x4e\141\x6d\145\x49\104\x3e\40\x6f\162\x20\74\x73\x61\155\x6c\x3a\105\x6e\x63\x72\171\x70\x74\x65\144\x49\x44\76\x20\x69\156\40\x3c\x73\141\155\154\72\123\165\x62\152\145\x63\164\76\x2e");
        goto RW;
        qL:
        throw new Exception("\115\157\162\x65\x20\164\x68\x61\x6e\x20\157\156\x65\x20\74\163\x61\x6d\x6c\72\x4e\x61\155\145\x49\x44\76\40\x6f\x72\x20\74\x73\x61\155\x6c\72\105\156\x63\x72\171\160\x74\x65\x64\x44\x3e\x20\x69\x6e\40\74\163\141\x6d\x6c\x3a\123\x75\x62\152\145\x63\x74\76\x2e");
        RW:
        $Pp = $Pp[0];
        if ($Pp->localName === "\x45\156\x63\162\x79\160\164\x65\144\x44\x61\x74\x61") {
            goto uj;
        }
        $this->nameId = Utilities::parseNameId($Pp);
        goto IK;
        uj:
        $this->encryptedNameId = $Pp;
        IK:
    }
    private function parseConditions(DOMElement $Z0)
    {
        $gg = Utilities::xpQuery($Z0, "\56\57\x73\x61\x6d\x6c\x5f\x61\163\163\x65\162\164\x69\x6f\x6e\72\103\157\156\144\151\x74\151\157\x6e\163");
        if (empty($gg)) {
            goto SS;
        }
        if (count($gg) > 1) {
            goto uL;
        }
        goto UQ;
        SS:
        return;
        goto UQ;
        uL:
        throw new Exception("\x4d\157\x72\x65\x20\164\150\x61\156\x20\x6f\156\145\x20\x3c\163\x61\x6d\x6c\72\103\x6f\x6e\x64\151\x74\151\x6f\x6e\163\x3e\x20\x69\x6e\x20\74\x73\141\x6d\x6c\72\101\163\x73\145\162\164\151\x6f\156\76\x2e");
        UQ:
        $gg = $gg[0];
        if (!$gg->hasAttribute("\116\x6f\x74\102\145\146\x6f\x72\145")) {
            goto gH;
        }
        $uD = Utilities::xsDateTimeToTimestamp($gg->getAttribute("\x4e\157\x74\x42\145\x66\157\x72\x65"));
        if (!($this->notBefore === NULL || $this->notBefore < $uD)) {
            goto zF;
        }
        $this->notBefore = $uD;
        zF:
        gH:
        if (!$gg->hasAttribute("\116\157\x74\x4f\x6e\117\x72\101\146\x74\x65\162")) {
            goto ah;
        }
        $jh = Utilities::xsDateTimeToTimestamp($gg->getAttribute("\116\x6f\164\x4f\x6e\x4f\x72\101\x66\164\145\162"));
        if (!($this->notOnOrAfter === NULL || $this->notOnOrAfter > $jh)) {
            goto sY;
        }
        $this->notOnOrAfter = $jh;
        sY:
        ah:
        $TV = $gg->firstChild;
        qd:
        if (!($TV !== NULL)) {
            goto Sj;
        }
        if (!$TV instanceof DOMText) {
            goto nx;
        }
        goto gb;
        nx:
        if (!($TV->namespaceURI !== "\165\162\x6e\72\x6f\x61\163\151\163\72\x6e\x61\x6d\145\x73\x3a\164\143\x3a\123\x41\115\114\x3a\x32\x2e\x30\72\x61\163\x73\x65\x72\x74\151\x6f\156")) {
            goto D7;
        }
        throw new Exception("\x55\156\x6b\x6e\x6f\x77\156\40\156\141\155\x65\x73\160\x61\x63\x65\x20\157\146\x20\143\157\156\x64\x69\x74\x69\x6f\156\x3a\x20" . var_export($TV->namespaceURI, TRUE));
        D7:
        switch ($TV->localName) {
            case "\101\x75\x64\151\x65\156\143\x65\122\x65\163\x74\162\151\143\164\x69\157\156":
                $OG = Utilities::extractStrings($TV, "\x75\x72\x6e\x3a\x6f\x61\163\151\163\72\156\x61\x6d\145\x73\x3a\164\143\72\x53\101\115\114\72\62\x2e\60\72\x61\163\163\x65\162\164\x69\157\156", "\101\165\144\x69\x65\156\143\145");
                if ($this->validAudiences === NULL) {
                    goto KV;
                }
                $this->validAudiences = array_intersect($this->validAudiences, $OG);
                goto Vi;
                KV:
                $this->validAudiences = $OG;
                Vi:
                goto nn;
            case "\x4f\x6e\145\x54\x69\155\145\125\163\145":
                goto nn;
            case "\x50\x72\157\170\171\x52\145\163\164\162\151\143\x74\x69\x6f\156":
                goto nn;
            default:
                throw new Exception("\125\156\153\156\157\x77\x6e\x20\x63\x6f\x6e\144\x69\164\151\x6f\156\x3a\x20" . var_export($TV->localName, TRUE));
        }
        NX:
        nn:
        gb:
        $TV = $TV->nextSibling;
        goto qd;
        Sj:
    }
    private function parseAuthnStatement(DOMElement $Z0)
    {
        $gI = Utilities::xpQuery($Z0, "\56\57\163\x61\155\x6c\137\141\x73\163\145\x72\164\151\x6f\156\72\x41\x75\164\150\x6e\123\x74\x61\164\145\155\x65\156\164");
        if (empty($gI)) {
            goto Tx;
        }
        if (count($gI) > 1) {
            goto lf;
        }
        goto wS;
        Tx:
        $this->authnInstant = NULL;
        return;
        goto wS;
        lf:
        throw new Exception("\115\157\x72\145\x20\164\150\141\x74\x20\x6f\156\x65\x20\74\x73\x61\155\x6c\72\101\x75\164\x68\156\123\164\141\164\145\x6d\x65\156\164\x3e\x20\151\156\40\74\163\x61\x6d\x6c\72\x41\x73\x73\145\x72\164\151\157\x6e\x3e\40\x6e\x6f\x74\40\163\165\160\x70\157\x72\164\x65\144\x2e");
        wS:
        $gH = $gI[0];
        if ($gH->hasAttribute("\101\x75\164\x68\x6e\x49\156\163\164\x61\x6e\164")) {
            goto Vm;
        }
        throw new Exception("\115\151\x73\x73\x69\156\x67\40\x72\x65\161\165\x69\x72\145\144\40\101\165\x74\x68\156\x49\x6e\163\x74\141\156\164\x20\x61\x74\164\x72\151\x62\165\164\x65\x20\157\156\40\x3c\x73\141\x6d\154\x3a\x41\165\164\x68\156\x53\x74\141\x74\145\x6d\x65\x6e\x74\76\x2e");
        Vm:
        $this->authnInstant = Utilities::xsDateTimeToTimestamp($gH->getAttribute("\x41\x75\x74\150\156\x49\156\x73\x74\141\x6e\x74"));
        if (!$gH->hasAttribute("\123\145\x73\x73\x69\x6f\156\x4e\x6f\164\x4f\x6e\117\162\101\x66\164\x65\162")) {
            goto Ri;
        }
        $this->sessionNotOnOrAfter = Utilities::xsDateTimeToTimestamp($gH->getAttribute("\123\145\x73\163\151\157\156\x4e\x6f\x74\x4f\x6e\117\162\x41\146\164\x65\162"));
        Ri:
        if (!$gH->hasAttribute("\x53\145\x73\163\151\x6f\x6e\111\x6e\x64\145\170")) {
            goto X2;
        }
        $this->sessionIndex = $gH->getAttribute("\123\x65\x73\x73\151\x6f\156\x49\156\144\145\x78");
        X2:
        $this->parseAuthnContext($gH);
    }
    private function parseAuthnContext(DOMElement $I6)
    {
        $PL = Utilities::xpQuery($I6, "\56\x2f\163\x61\155\x6c\x5f\141\x73\163\145\x72\164\x69\x6f\156\72\101\x75\x74\150\x6e\103\157\156\164\145\x78\x74");
        if (count($PL) > 1) {
            goto Ac;
        }
        if (empty($PL)) {
            goto BD;
        }
        goto SI;
        Ac:
        throw new Exception("\115\x6f\162\x65\x20\164\x68\x61\156\40\x6f\156\145\40\x3c\163\x61\x6d\154\72\101\x75\164\150\156\103\x6f\x6e\164\145\170\164\x3e\40\151\156\40\74\x73\141\x6d\154\72\x41\165\164\x68\156\123\164\141\x74\x65\155\x65\156\164\x3e\56");
        goto SI;
        BD:
        throw new Exception("\115\151\163\163\x69\x6e\x67\x20\162\x65\x71\165\151\162\145\144\x20\74\x73\141\x6d\x6c\72\101\165\164\150\x6e\103\x6f\156\x74\x65\170\164\x3e\40\151\156\40\74\163\141\155\154\72\x41\x75\164\x68\x6e\x53\164\141\x74\x65\x6d\x65\x6e\164\76\56");
        SI:
        $Xt = $PL[0];
        $ua = Utilities::xpQuery($Xt, "\x2e\x2f\163\141\155\x6c\137\x61\163\163\x65\162\164\151\x6f\x6e\72\x41\x75\x74\x68\x6e\103\x6f\x6e\164\145\170\x74\x44\145\x63\x6c\x52\145\146");
        if (count($ua) > 1) {
            goto Ya;
        }
        if (count($ua) === 1) {
            goto qK;
        }
        goto m7;
        Ya:
        throw new Exception("\x4d\x6f\162\x65\x20\164\x68\x61\x6e\x20\x6f\x6e\x65\x20\x3c\163\141\155\x6c\x3a\x41\165\x74\150\x6e\103\157\x6e\x74\145\170\164\x44\145\143\154\122\145\x66\x3e\40\x66\x6f\165\156\x64\x3f");
        goto m7;
        qK:
        $this->setAuthnContextDeclRef(trim($ua[0]->textContent));
        m7:
        $Au = Utilities::xpQuery($Xt, "\56\57\163\x61\x6d\x6c\137\141\163\163\x65\x72\164\151\x6f\x6e\x3a\101\x75\164\x68\x6e\x43\x6f\x6e\164\x65\170\164\x44\x65\143\x6c");
        if (count($Au) > 1) {
            goto m_;
        }
        if (count($Au) === 1) {
            goto JC;
        }
        goto AW;
        m_:
        throw new Exception("\115\x6f\162\x65\x20\164\x68\x61\156\x20\157\x6e\x65\40\x3c\x73\x61\x6d\154\72\101\165\164\x68\x6e\x43\x6f\156\164\145\170\x74\x44\145\x63\x6c\x3e\x20\x66\x6f\165\156\x64\x3f");
        goto AW;
        JC:
        $this->setAuthnContextDecl(new SAML2_XML_Chunk($Au[0]));
        AW:
        $uJ = Utilities::xpQuery($Xt, "\x2e\x2f\163\x61\155\154\137\x61\163\163\x65\162\x74\151\157\x6e\x3a\101\x75\164\150\156\x43\157\156\x74\x65\170\x74\103\x6c\141\163\x73\122\x65\146");
        if (count($uJ) > 1) {
            goto HO;
        }
        if (count($uJ) === 1) {
            goto NC;
        }
        goto ay;
        HO:
        throw new Exception("\x4d\157\162\x65\40\164\x68\141\x6e\40\157\x6e\x65\40\x3c\x73\x61\155\154\72\101\165\x74\x68\x6e\x43\157\x6e\x74\x65\170\164\103\154\x61\x73\x73\x52\x65\146\76\x20\x69\x6e\x20\74\x73\x61\x6d\154\x3a\101\x75\x74\x68\x6e\x43\157\x6e\164\x65\170\x74\x3e\x2e");
        goto ay;
        NC:
        $this->setAuthnContextClassRef(trim($uJ[0]->textContent));
        ay:
        if (!(empty($this->authnContextClassRef) && empty($this->authnContextDecl) && empty($this->authnContextDeclRef))) {
            goto H6;
        }
        throw new Exception("\115\151\163\x73\151\x6e\x67\x20\145\151\164\x68\x65\162\x20\x3c\163\141\x6d\154\72\101\x75\164\150\x6e\x43\157\x6e\x74\145\170\164\103\154\141\x73\x73\122\145\146\x3e\40\157\162\x20\x3c\x73\x61\155\x6c\x3a\101\x75\x74\x68\156\103\157\x6e\164\x65\170\x74\x44\x65\143\154\122\x65\146\x3e\x20\x6f\162\40\x3c\x73\x61\x6d\x6c\72\101\165\164\x68\x6e\x43\x6f\156\x74\145\x78\x74\x44\145\x63\154\x3e");
        H6:
        $this->AuthenticatingAuthority = Utilities::extractStrings($Xt, "\165\162\156\72\x6f\x61\x73\x69\x73\x3a\x6e\x61\x6d\x65\163\72\164\143\x3a\x53\x41\115\114\72\x32\x2e\x30\x3a\141\x73\163\x65\x72\x74\x69\x6f\156", "\x41\x75\x74\150\x65\156\x74\x69\143\141\164\x69\x6e\x67\x41\x75\164\x68\x6f\162\x69\164\x79");
    }
    private function parseAttributes(DOMElement $Z0)
    {
        $s4 = TRUE;
        $Ra = Utilities::xpQuery($Z0, "\x2e\x2f\x73\141\155\x6c\x5f\141\163\163\145\162\x74\151\157\x6e\72\101\164\164\x72\151\x62\165\x74\145\123\164\x61\164\145\155\145\x6e\x74\x2f\x73\x61\155\x6c\x5f\x61\163\x73\x65\x72\x74\151\x6f\x6e\x3a\101\x74\164\x72\151\x62\165\164\x65");
        foreach ($Ra as $i5) {
            if ($i5->hasAttribute("\116\x61\155\145")) {
                goto cM;
            }
            throw new Exception("\115\x69\x73\163\151\x6e\147\x20\x6e\141\x6d\145\x20\157\156\40\74\163\x61\x6d\154\72\101\164\x74\x72\x69\142\165\164\x65\x3e\40\145\x6c\x65\x6d\145\x6e\164\x2e");
            cM:
            $Fg = $i5->getAttribute("\116\141\155\145");
            if ($i5->hasAttribute("\x4e\x61\x6d\x65\x46\157\x72\x6d\x61\164")) {
                goto R0;
            }
            $qI = "\165\x72\x6e\x3a\x6f\141\163\x69\x73\x3a\x6e\141\x6d\145\163\x3a\164\143\x3a\123\101\115\114\72\61\x2e\61\x3a\x6e\x61\x6d\145\x69\144\55\146\157\162\155\x61\x74\72\x75\156\163\160\x65\143\151\x66\x69\x65\144";
            goto KY;
            R0:
            $qI = $i5->getAttribute("\x4e\x61\x6d\x65\x46\157\x72\155\141\x74");
            KY:
            if ($s4) {
                goto ED;
            }
            if (!($this->nameFormat !== $qI)) {
                goto kQ;
            }
            $this->nameFormat = "\x75\x72\156\x3a\157\141\163\x69\x73\x3a\156\141\x6d\145\x73\72\164\x63\x3a\123\101\x4d\114\72\61\56\x31\72\x6e\x61\155\x65\x69\x64\x2d\146\157\x72\155\141\164\x3a\x75\156\163\x70\x65\143\151\146\x69\x65\144";
            kQ:
            goto S1;
            ED:
            $this->nameFormat = $qI;
            $s4 = FALSE;
            S1:
            if (array_key_exists($Fg, $this->attributes)) {
                goto kk;
            }
            $this->attributes[$Fg] = array();
            kk:
            $Ig = Utilities::xpQuery($i5, "\56\x2f\163\x61\x6d\154\x5f\x61\x73\163\145\x72\164\151\157\156\x3a\101\x74\x74\162\x69\142\165\164\145\x56\x61\154\165\145");
            foreach ($Ig as $yX) {
                $this->attributes[$Fg][] = trim($yX->textContent);
                e8:
            }
            Mr:
            SB:
        }
        dn:
    }
    private function parseEncryptedAttributes(DOMElement $Z0)
    {
        $this->encryptedAttribute = Utilities::xpQuery($Z0, "\56\57\163\x61\x6d\154\137\x61\163\x73\x65\162\164\151\x6f\156\x3a\x41\x74\x74\162\151\142\x75\x74\145\x53\x74\141\x74\x65\x6d\145\x6e\164\x2f\x73\x61\155\x6c\x5f\x61\163\163\145\162\164\x69\x6f\156\72\105\x6e\x63\162\171\160\x74\x65\144\101\x74\x74\x72\x69\142\165\x74\x65");
    }
    private function parseSignature(DOMElement $Z0)
    {
        $gF = Utilities::validateElement($Z0);
        if (!($gF !== FALSE)) {
            goto XK;
        }
        $this->wasSignedAtConstruction = TRUE;
        $this->certificates = $gF["\103\145\x72\164\151\x66\151\x63\x61\164\145\163"];
        $this->signatureData = $gF;
        XK:
    }
    public function validate(XMLSecurityKey $eQ)
    {
        if (!($this->signatureData === NULL)) {
            goto wG;
        }
        return FALSE;
        wG:
        Utilities::validateSignature($this->signatureData, $eQ);
        return TRUE;
    }
    public function getId()
    {
        return $this->id;
    }
    public function setId($kF)
    {
        $this->id = $kF;
    }
    public function getIssueInstant()
    {
        return $this->issueInstant;
    }
    public function setIssueInstant($XM)
    {
        $this->issueInstant = $XM;
    }
    public function getIssuer()
    {
        return $this->issuer;
    }
    public function setIssuer($YM)
    {
        $this->issuer = $YM;
    }
    public function getNameId()
    {
        if (!($this->encryptedNameId !== NULL)) {
            goto O2;
        }
        throw new Exception("\x41\x74\x74\x65\155\x70\164\x65\x64\x20\x74\x6f\x20\x72\x65\x74\x72\151\x65\166\x65\40\145\156\143\x72\x79\x70\x74\x65\144\x20\x4e\141\x6d\x65\111\x44\x20\167\x69\x74\x68\157\165\x74\40\144\x65\x63\x72\171\x70\x74\151\156\147\x20\x69\x74\40\146\x69\162\163\x74\56");
        O2:
        return $this->nameId;
    }
    public function setNameId($Pp)
    {
        $this->nameId = $Pp;
    }
    public function isNameIdEncrypted()
    {
        if (!($this->encryptedNameId !== NULL)) {
            goto fj;
        }
        return TRUE;
        fj:
        return FALSE;
    }
    public function encryptNameId(XMLSecurityKey $eQ)
    {
        $S9 = new DOMDocument();
        $Jp = $S9->createElement("\x72\x6f\x6f\x74");
        $S9->appendChild($Jp);
        Utilities::addNameId($Jp, $this->nameId);
        $Pp = $Jp->firstChild;
        Utilities::getContainer()->debugMessage($Pp, "\145\x6e\x63\162\x79\x70\164");
        $RP = new XMLSecEnc();
        $RP->setNode($Pp);
        $RP->type = XMLSecEnc::Element;
        $HZ = new XMLSecurityKey(XMLSecurityKey::AES128_CBC);
        $HZ->generateSessionKey();
        $RP->encryptKey($eQ, $HZ);
        $this->encryptedNameId = $RP->encryptNode($HZ);
        $this->nameId = NULL;
    }
    public function decryptNameId(XMLSecurityKey $eQ, array $qo = array())
    {
        if (!($this->encryptedNameId === NULL)) {
            goto pQ;
        }
        return;
        pQ:
        $Pp = Utilities::decryptElement($this->encryptedNameId, $eQ, $qo);
        Utilities::getContainer()->debugMessage($Pp, "\x64\145\x63\162\171\160\164");
        $this->nameId = Utilities::parseNameId($Pp);
        $this->encryptedNameId = NULL;
    }
    public function decryptAttributes(XMLSecurityKey $eQ, array $qo = array())
    {
        if (!($this->encryptedAttribute === NULL)) {
            goto Ad;
        }
        return;
        Ad:
        $s4 = TRUE;
        $Ra = $this->encryptedAttribute;
        foreach ($Ra as $rj) {
            $i5 = Utilities::decryptElement($rj->getElementsByTagName("\105\156\143\x72\171\160\164\145\x64\x44\x61\164\141")->item(0), $eQ, $qo);
            if ($i5->hasAttribute("\x4e\x61\x6d\145")) {
                goto kG;
            }
            throw new Exception("\115\x69\163\163\151\x6e\147\x20\x6e\141\155\x65\40\157\x6e\x20\74\163\x61\x6d\154\72\x41\164\x74\x72\x69\142\x75\x74\x65\x3e\x20\145\154\x65\x6d\145\x6e\x74\x2e");
            kG:
            $Fg = $i5->getAttribute("\x4e\141\x6d\x65");
            if ($i5->hasAttribute("\116\x61\155\x65\x46\x6f\162\x6d\141\164")) {
                goto K1;
            }
            $qI = "\165\x72\156\72\157\x61\163\151\x73\x3a\156\x61\x6d\145\x73\72\164\x63\x3a\x53\x41\x4d\x4c\72\62\x2e\x30\72\141\x74\x74\162\x6e\x61\155\145\55\x66\x6f\162\155\x61\x74\x3a\165\156\x73\160\x65\x63\x69\146\x69\145\x64";
            goto GM;
            K1:
            $qI = $i5->getAttribute("\116\x61\x6d\x65\x46\157\x72\155\x61\x74");
            GM:
            if ($s4) {
                goto Rz;
            }
            if (!($this->nameFormat !== $qI)) {
                goto g6;
            }
            $this->nameFormat = "\165\x72\156\x3a\157\141\163\151\163\x3a\156\x61\x6d\145\x73\x3a\x74\x63\x3a\123\101\x4d\114\72\62\56\x30\x3a\141\x74\x74\x72\x6e\x61\x6d\x65\x2d\146\157\162\155\x61\x74\x3a\165\x6e\163\x70\145\x63\151\146\x69\x65\144";
            g6:
            goto uK;
            Rz:
            $this->nameFormat = $qI;
            $s4 = FALSE;
            uK:
            if (array_key_exists($Fg, $this->attributes)) {
                goto H3;
            }
            $this->attributes[$Fg] = array();
            H3:
            $Ig = Utilities::xpQuery($i5, "\56\57\163\x61\155\x6c\137\x61\x73\x73\145\162\x74\x69\157\156\72\x41\164\x74\x72\151\142\x75\x74\x65\x56\141\x6c\x75\x65");
            foreach ($Ig as $yX) {
                $this->attributes[$Fg][] = trim($yX->textContent);
                ka:
            }
            A7:
            Dm:
        }
        Yt:
    }
    public function getNotBefore()
    {
        return $this->notBefore;
    }
    public function setNotBefore($uD)
    {
        $this->notBefore = $uD;
    }
    public function getNotOnOrAfter()
    {
        return $this->notOnOrAfter;
    }
    public function setNotOnOrAfter($jh)
    {
        $this->notOnOrAfter = $jh;
    }
    public function setEncryptedAttributes($H3)
    {
        $this->requiredEncAttributes = $H3;
    }
    public function getValidAudiences()
    {
        return $this->validAudiences;
    }
    public function setValidAudiences(array $S8 = NULL)
    {
        $this->validAudiences = $S8;
    }
    public function getAuthnInstant()
    {
        return $this->authnInstant;
    }
    public function setAuthnInstant($ZH)
    {
        $this->authnInstant = $ZH;
    }
    public function getSessionNotOnOrAfter()
    {
        return $this->sessionNotOnOrAfter;
    }
    public function setSessionNotOnOrAfter($wi)
    {
        $this->sessionNotOnOrAfter = $wi;
    }
    public function getSessionIndex()
    {
        return $this->sessionIndex;
    }
    public function setSessionIndex($u8)
    {
        $this->sessionIndex = $u8;
    }
    public function getAuthnContext()
    {
        if (empty($this->authnContextClassRef)) {
            goto lX;
        }
        return $this->authnContextClassRef;
        lX:
        if (empty($this->authnContextDeclRef)) {
            goto lS;
        }
        return $this->authnContextDeclRef;
        lS:
        return NULL;
    }
    public function setAuthnContext($rR)
    {
        $this->setAuthnContextClassRef($rR);
    }
    public function getAuthnContextClassRef()
    {
        return $this->authnContextClassRef;
    }
    public function setAuthnContextClassRef($U0)
    {
        $this->authnContextClassRef = $U0;
    }
    public function setAuthnContextDecl(SAML2_XML_Chunk $eK)
    {
        if (empty($this->authnContextDeclRef)) {
            goto NT;
        }
        throw new Exception("\x41\165\x74\150\x6e\x43\157\156\164\145\170\x74\104\x65\143\154\x52\145\x66\x20\x69\163\x20\x61\154\162\145\x61\x64\x79\40\x72\145\x67\151\163\164\145\162\x65\144\x21\x20\115\x61\x79\x20\157\156\x6c\171\40\150\x61\166\x65\40\145\x69\x74\x68\x65\x72\x20\x61\x20\104\x65\143\154\x20\x6f\x72\40\141\40\x44\x65\143\154\122\x65\146\54\x20\156\157\164\x20\x62\157\164\x68\41");
        NT:
        $this->authnContextDecl = $eK;
    }
    public function getAuthnContextDecl()
    {
        return $this->authnContextDecl;
    }
    public function setAuthnContextDeclRef($Uf)
    {
        if (empty($this->authnContextDecl)) {
            goto Uu;
        }
        throw new Exception("\x41\x75\x74\x68\156\x43\x6f\156\164\145\x78\164\x44\145\143\x6c\x20\151\x73\40\141\x6c\x72\x65\141\x64\171\40\162\145\x67\151\163\x74\145\x72\x65\144\x21\40\115\x61\171\x20\157\156\154\x79\x20\x68\141\x76\145\40\145\151\164\x68\145\x72\x20\141\x20\x44\145\x63\x6c\40\157\162\x20\141\x20\104\x65\143\154\x52\x65\146\54\x20\156\157\x74\x20\142\x6f\164\x68\41");
        Uu:
        $this->authnContextDeclRef = $Uf;
    }
    public function getAuthnContextDeclRef()
    {
        return $this->authnContextDeclRef;
    }
    public function getAuthenticatingAuthority()
    {
        return $this->AuthenticatingAuthority;
    }
    public function setAuthenticatingAuthority($yN)
    {
        $this->AuthenticatingAuthority = $yN;
    }
    public function getAttributes()
    {
        return $this->attributes;
    }
    public function setAttributes(array $Ra)
    {
        $this->attributes = $Ra;
    }
    public function getAttributeNameFormat()
    {
        return $this->nameFormat;
    }
    public function setAttributeNameFormat($qI)
    {
        $this->nameFormat = $qI;
    }
    public function getSubjectConfirmation()
    {
        return $this->SubjectConfirmation;
    }
    public function setSubjectConfirmation(array $Zn)
    {
        $this->SubjectConfirmation = $Zn;
    }
    public function getSignatureKey()
    {
        return $this->signatureKey;
    }
    public function getSignatureData()
    {
        return $this->signatureData;
    }
    public function setSignatureKey(XMLsecurityKey $qF = NULL)
    {
        $this->signatureKey = $qF;
    }
    public function getEncryptionKey()
    {
        return $this->encryptionKey;
    }
    public function setEncryptionKey(XMLSecurityKey $M2 = NULL)
    {
        $this->encryptionKey = $M2;
    }
    public function setCertificates(array $hR)
    {
        $this->certificates = $hR;
    }
    public function getCertificates()
    {
        return $this->certificates;
    }
    public function getWasSignedAtConstruction()
    {
        return $this->wasSignedAtConstruction;
    }
    public function toXML(DOMNode $ED = NULL)
    {
        if ($ED === NULL) {
            goto oA;
        }
        $HT = $ED->ownerDocument;
        goto LK;
        oA:
        $HT = new DOMDocument();
        $ED = $HT;
        LK:
        $Jp = $HT->createElementNS("\x75\162\x6e\x3a\157\141\x73\x69\163\x3a\x6e\141\x6d\145\163\x3a\164\x63\72\x53\101\x4d\114\72\x32\x2e\x30\x3a\x61\163\163\x65\x72\x74\151\157\x6e", "\163\x61\155\154\72" . "\x41\163\x73\145\162\164\151\157\x6e");
        $ED->appendChild($Jp);
        $Jp->setAttributeNS("\x75\162\x6e\72\x6f\x61\x73\151\x73\x3a\x6e\x61\155\145\x73\72\164\x63\72\x53\101\115\x4c\72\62\56\60\72\160\x72\157\x74\157\143\157\x6c", "\x73\141\x6d\154\160\x3a\x74\x6d\160", "\164\x6d\160");
        $Jp->removeAttributeNS("\x75\x72\x6e\x3a\x6f\x61\x73\151\163\72\156\141\x6d\x65\x73\72\x74\x63\72\123\x41\x4d\114\72\62\56\x30\72\x70\x72\x6f\164\157\143\x6f\154", "\x74\x6d\x70");
        $Jp->setAttributeNS("\x68\x74\164\160\72\x2f\x2f\x77\x77\167\56\167\x33\56\157\x72\x67\57\62\x30\x30\x31\x2f\x58\x4d\x4c\x53\x63\150\145\x6d\141\x2d\x69\x6e\163\164\x61\156\143\145", "\x78\x73\x69\x3a\x74\x6d\160", "\x74\x6d\160");
        $Jp->removeAttributeNS("\150\x74\x74\160\72\57\x2f\x77\x77\167\56\x77\x33\56\x6f\162\147\x2f\x32\x30\x30\61\x2f\x58\115\114\123\143\x68\145\x6d\x61\x2d\151\x6e\163\164\x61\x6e\x63\145", "\x74\x6d\160");
        $Jp->setAttributeNS("\x68\164\164\x70\72\57\57\167\x77\x77\x2e\x77\63\x2e\157\162\x67\57\62\60\x30\x31\x2f\130\115\x4c\123\x63\x68\145\155\141", "\x78\x73\72\x74\x6d\160", "\x74\x6d\x70");
        $Jp->removeAttributeNS("\150\x74\x74\x70\72\57\x2f\167\167\167\x2e\x77\63\56\x6f\162\147\57\62\x30\x30\x31\x2f\130\x4d\114\123\x63\x68\145\x6d\141", "\x74\155\x70");
        $Jp->setAttribute("\x49\104", $this->id);
        $Jp->setAttribute("\x56\145\x72\163\151\x6f\156", "\x32\x2e\60");
        $Jp->setAttribute("\111\163\x73\x75\x65\111\x6e\163\x74\x61\156\164", gmdate("\x59\x2d\x6d\x2d\144\134\124\110\x3a\151\72\163\x5c\x5a", $this->issueInstant));
        $YM = Utilities::addString($Jp, "\x75\162\x6e\x3a\157\141\163\151\163\x3a\156\141\x6d\x65\163\x3a\x74\x63\x3a\123\101\x4d\x4c\x3a\x32\x2e\x30\72\x61\163\x73\x65\162\164\x69\x6f\x6e", "\163\x61\155\154\72\x49\x73\x73\x75\x65\x72", $this->issuer);
        $this->addSubject($Jp);
        $this->addConditions($Jp);
        $this->addAuthnStatement($Jp);
        if ($this->requiredEncAttributes == FALSE) {
            goto kc;
        }
        $this->addEncryptedAttributeStatement($Jp);
        goto WH;
        kc:
        $this->addAttributeStatement($Jp);
        WH:
        if (!($this->signatureKey !== NULL)) {
            goto JE;
        }
        Utilities::insertSignature($this->signatureKey, $this->certificates, $Jp, $YM->nextSibling);
        JE:
        return $Jp;
    }
    private function addSubject(DOMElement $Jp)
    {
        if (!($this->nameId === NULL && $this->encryptedNameId === NULL)) {
            goto cQ;
        }
        return;
        cQ:
        $gp = $Jp->ownerDocument->createElementNS("\165\162\156\x3a\157\x61\x73\151\163\72\x6e\x61\155\x65\x73\72\164\143\x3a\123\x41\115\114\x3a\62\x2e\x30\x3a\x61\x73\163\x65\162\164\151\x6f\156", "\x73\141\155\154\x3a\123\165\x62\152\x65\x63\x74");
        $Jp->appendChild($gp);
        if ($this->encryptedNameId === NULL) {
            goto gZ;
        }
        $TZ = $gp->ownerDocument->createElementNS("\x75\162\x6e\x3a\x6f\x61\163\151\163\72\x6e\141\x6d\145\163\72\164\x63\72\123\101\115\x4c\x3a\x32\x2e\60\72\141\163\x73\145\162\164\x69\157\156", "\163\x61\x6d\154\72" . "\105\x6e\x63\x72\x79\160\164\145\144\111\104");
        $gp->appendChild($TZ);
        $TZ->appendChild($gp->ownerDocument->importNode($this->encryptedNameId, TRUE));
        goto Sc;
        gZ:
        Utilities::addNameId($gp, $this->nameId);
        Sc:
        foreach ($this->SubjectConfirmation as $WF) {
            $WF->toXML($gp);
            h_:
        }
        OT:
    }
    private function addConditions(DOMElement $Jp)
    {
        $HT = $Jp->ownerDocument;
        $gg = $HT->createElementNS("\x75\x72\156\x3a\x6f\x61\163\x69\x73\x3a\x6e\x61\155\145\163\x3a\164\x63\72\123\x41\115\x4c\x3a\x32\x2e\x30\x3a\141\x73\163\145\162\x74\151\157\156", "\163\x61\x6d\x6c\72\103\x6f\x6e\144\151\x74\x69\x6f\156\x73");
        $Jp->appendChild($gg);
        if (!($this->notBefore !== NULL)) {
            goto C7;
        }
        $gg->setAttribute("\x4e\x6f\x74\x42\x65\x66\x6f\x72\145", gmdate("\131\55\x6d\55\144\x5c\124\x48\x3a\151\72\x73\x5c\132", $this->notBefore));
        C7:
        if (!($this->notOnOrAfter !== NULL)) {
            goto S7;
        }
        $gg->setAttribute("\x4e\x6f\164\117\156\117\x72\101\146\164\x65\162", gmdate("\x59\x2d\x6d\x2d\x64\134\x54\110\x3a\151\72\163\134\x5a", $this->notOnOrAfter));
        S7:
        if (!($this->validAudiences !== NULL)) {
            goto EM;
        }
        $s8 = $HT->createElementNS("\x75\x72\x6e\x3a\x6f\141\163\151\x73\72\x6e\141\x6d\x65\x73\72\164\x63\72\x53\x41\x4d\x4c\x3a\62\x2e\60\x3a\x61\163\x73\145\x72\164\151\x6f\156", "\163\141\x6d\x6c\72\x41\165\144\x69\145\x6e\143\x65\x52\x65\x73\164\162\x69\143\x74\x69\157\x6e");
        $gg->appendChild($s8);
        Utilities::addStrings($s8, "\165\x72\156\72\x6f\141\163\x69\163\x3a\x6e\x61\x6d\145\163\x3a\164\143\x3a\123\x41\x4d\x4c\72\x32\56\x30\x3a\x61\x73\163\145\162\x74\151\157\x6e", "\x73\x61\x6d\154\x3a\101\165\x64\151\145\x6e\143\x65", FALSE, $this->validAudiences);
        EM:
    }
    private function addAuthnStatement(DOMElement $Jp)
    {
        if (!($this->authnInstant === NULL || $this->authnContextClassRef === NULL && $this->authnContextDecl === NULL && $this->authnContextDeclRef === NULL)) {
            goto kh;
        }
        return;
        kh:
        $HT = $Jp->ownerDocument;
        $I6 = $HT->createElementNS("\165\x72\x6e\72\x6f\x61\x73\x69\163\72\156\x61\155\x65\163\x3a\164\143\x3a\123\101\115\x4c\x3a\62\x2e\x30\72\x61\163\x73\145\x72\x74\x69\x6f\x6e", "\163\141\x6d\154\72\101\165\164\150\156\123\x74\141\164\x65\x6d\x65\156\164");
        $Jp->appendChild($I6);
        $I6->setAttribute("\101\x75\x74\x68\156\x49\156\163\x74\x61\x6e\x74", gmdate("\x59\55\x6d\x2d\144\134\124\x48\x3a\x69\x3a\x73\x5c\132", $this->authnInstant));
        if (!($this->sessionNotOnOrAfter !== NULL)) {
            goto f5;
        }
        $I6->setAttribute("\x53\145\163\x73\x69\157\x6e\116\157\164\117\156\117\162\x41\146\164\x65\162", gmdate("\131\x2d\x6d\x2d\144\134\124\110\72\x69\72\x73\x5c\x5a", $this->sessionNotOnOrAfter));
        f5:
        if (!($this->sessionIndex !== NULL)) {
            goto jL;
        }
        $I6->setAttribute("\x53\145\163\x73\151\x6f\x6e\x49\x6e\x64\x65\170", $this->sessionIndex);
        jL:
        $Xt = $HT->createElementNS("\x75\162\156\72\x6f\x61\163\x69\163\72\156\141\x6d\145\x73\x3a\x74\143\72\x53\101\115\114\x3a\62\56\x30\x3a\x61\x73\x73\145\x72\164\151\x6f\x6e", "\163\x61\x6d\x6c\72\101\x75\x74\x68\x6e\x43\x6f\x6e\164\145\170\x74");
        $I6->appendChild($Xt);
        if (empty($this->authnContextClassRef)) {
            goto zN;
        }
        Utilities::addString($Xt, "\x75\162\156\x3a\157\x61\163\x69\163\x3a\x6e\x61\155\x65\163\72\164\x63\72\x53\x41\115\114\x3a\x32\56\x30\72\x61\163\x73\145\162\164\x69\x6f\156", "\x73\141\x6d\154\72\101\165\x74\x68\156\x43\x6f\156\164\145\170\x74\103\x6c\x61\x73\163\x52\x65\x66", $this->authnContextClassRef);
        zN:
        if (empty($this->authnContextDecl)) {
            goto FI;
        }
        $this->authnContextDecl->toXML($Xt);
        FI:
        if (empty($this->authnContextDeclRef)) {
            goto vm;
        }
        Utilities::addString($Xt, "\x75\162\156\72\157\x61\x73\x69\x73\72\x6e\x61\155\145\163\x3a\164\143\x3a\x53\x41\115\114\x3a\x32\56\60\x3a\141\163\163\x65\162\x74\151\x6f\x6e", "\163\141\155\x6c\72\x41\x75\x74\x68\x6e\103\157\156\x74\x65\170\164\104\x65\143\x6c\x52\145\x66", $this->authnContextDeclRef);
        vm:
        Utilities::addStrings($Xt, "\x75\162\x6e\x3a\157\x61\163\x69\x73\x3a\x6e\x61\155\x65\163\x3a\164\x63\72\x53\101\115\x4c\72\62\56\x30\x3a\141\163\163\145\x72\164\x69\x6f\156", "\x73\141\155\x6c\x3a\x41\x75\x74\150\x65\156\164\x69\143\x61\x74\151\x6e\147\x41\165\x74\150\x6f\x72\x69\x74\171", FALSE, $this->AuthenticatingAuthority);
    }
    private function addAttributeStatement(DOMElement $Jp)
    {
        if (!empty($this->attributes)) {
            goto jA;
        }
        return;
        jA:
        $HT = $Jp->ownerDocument;
        $J1 = $HT->createElementNS("\x75\x72\x6e\72\x6f\x61\x73\x69\163\72\156\x61\x6d\145\x73\x3a\x74\x63\72\123\x41\115\x4c\72\62\56\x30\72\x61\163\163\x65\x72\x74\x69\x6f\156", "\x73\x61\155\154\x3a\x41\x74\x74\162\151\x62\x75\164\145\123\164\141\x74\145\155\x65\156\164");
        $Jp->appendChild($J1);
        foreach ($this->attributes as $Fg => $Ig) {
            $i5 = $HT->createElementNS("\x75\162\156\72\x6f\x61\163\151\163\72\x6e\x61\x6d\145\x73\72\x74\x63\72\x53\101\x4d\x4c\x3a\x32\x2e\x30\x3a\x61\x73\163\x65\x72\164\151\x6f\156", "\x73\x61\155\x6c\x3a\x41\164\x74\x72\x69\x62\165\164\x65");
            $J1->appendChild($i5);
            $i5->setAttribute("\x4e\x61\155\145", $Fg);
            if (!($this->nameFormat !== "\165\x72\156\72\x6f\141\x73\151\163\x3a\156\x61\x6d\x65\163\72\164\x63\x3a\x53\101\115\114\72\x32\56\x30\72\141\x74\x74\x72\x6e\141\155\145\x2d\146\157\162\155\x61\x74\72\x75\x6e\163\x70\x65\143\x69\x66\x69\145\144")) {
                goto gy;
            }
            $i5->setAttribute("\x4e\x61\x6d\x65\106\157\162\155\141\164", $this->nameFormat);
            gy:
            foreach ($Ig as $yX) {
                if (is_string($yX)) {
                    goto wp;
                }
                if (is_int($yX)) {
                    goto Kd;
                }
                $Hm = NULL;
                goto mX;
                wp:
                $Hm = "\x78\163\72\x73\164\x72\151\x6e\147";
                goto mX;
                Kd:
                $Hm = "\170\163\x3a\151\156\164\x65\x67\145\162";
                mX:
                $NK = $HT->createElementNS("\165\162\x6e\72\x6f\x61\x73\151\x73\x3a\x6e\x61\155\x65\163\x3a\x74\x63\x3a\x53\101\x4d\114\72\x32\x2e\x30\x3a\x61\163\163\x65\162\x74\x69\x6f\156", "\163\141\155\x6c\72\x41\x74\164\162\x69\x62\x75\164\x65\126\141\x6c\165\x65");
                $i5->appendChild($NK);
                if (!($Hm !== NULL)) {
                    goto Lm;
                }
                $NK->setAttributeNS("\150\x74\x74\x70\72\57\x2f\x77\x77\167\x2e\x77\63\56\x6f\162\147\57\x32\x30\60\61\x2f\x58\x4d\x4c\123\x63\x68\x65\155\x61\x2d\x69\156\x73\164\141\156\143\x65", "\x78\x73\151\72\164\171\160\x65", $Hm);
                Lm:
                if (!is_null($yX)) {
                    goto h4;
                }
                $NK->setAttributeNS("\150\x74\x74\160\x3a\57\x2f\167\x77\x77\x2e\x77\63\56\x6f\x72\147\57\62\x30\x30\x31\x2f\x58\x4d\x4c\123\x63\150\145\155\141\x2d\151\x6e\x73\164\141\x6e\x63\x65", "\x78\163\151\72\x6e\x69\154", "\x74\x72\165\x65");
                h4:
                if ($yX instanceof DOMNodeList) {
                    goto WA;
                }
                $NK->appendChild($HT->createTextNode($yX));
                goto wq;
                WA:
                $mp = 0;
                rS:
                if (!($mp < $yX->length)) {
                    goto SK;
                }
                $TV = $HT->importNode($yX->item($mp), TRUE);
                $NK->appendChild($TV);
                MY:
                $mp++;
                goto rS;
                SK:
                wq:
                p8:
            }
            ZG:
            uv:
        }
        T8:
    }
    private function addEncryptedAttributeStatement(DOMElement $Jp)
    {
        if (!($this->requiredEncAttributes == FALSE)) {
            goto l9;
        }
        return;
        l9:
        $HT = $Jp->ownerDocument;
        $J1 = $HT->createElementNS("\165\162\156\72\157\x61\x73\151\163\72\x6e\x61\155\145\x73\x3a\164\143\x3a\x53\101\115\x4c\72\62\56\60\x3a\x61\163\163\145\162\x74\151\x6f\156", "\163\141\x6d\x6c\x3a\101\x74\x74\x72\x69\142\x75\x74\x65\x53\164\141\164\x65\x6d\145\x6e\x74");
        $Jp->appendChild($J1);
        foreach ($this->attributes as $Fg => $Ig) {
            $xx = new DOMDocument();
            $i5 = $xx->createElementNS("\165\162\156\72\157\141\x73\x69\x73\x3a\x6e\x61\155\145\163\x3a\164\143\72\123\x41\x4d\114\72\62\56\60\72\141\x73\x73\x65\162\x74\151\157\156", "\163\x61\155\154\72\x41\164\x74\162\151\142\165\x74\x65");
            $i5->setAttribute("\116\x61\155\145", $Fg);
            $xx->appendChild($i5);
            if (!($this->nameFormat !== "\x75\162\x6e\72\157\141\x73\151\x73\x3a\156\141\x6d\145\163\x3a\x74\143\72\123\101\115\x4c\72\62\56\x30\72\141\164\164\x72\x6e\x61\155\145\55\146\157\162\x6d\x61\x74\72\x75\x6e\x73\x70\145\143\151\146\x69\x65\144")) {
                goto hC;
            }
            $i5->setAttribute("\x4e\x61\155\145\106\x6f\162\x6d\141\164", $this->nameFormat);
            hC:
            foreach ($Ig as $yX) {
                if (is_string($yX)) {
                    goto LE;
                }
                if (is_int($yX)) {
                    goto PM;
                }
                $Hm = NULL;
                goto kR;
                LE:
                $Hm = "\x78\163\72\163\x74\x72\151\156\x67";
                goto kR;
                PM:
                $Hm = "\170\x73\72\x69\x6e\164\x65\x67\x65\x72";
                kR:
                $NK = $xx->createElementNS("\x75\x72\156\72\x6f\141\163\151\163\72\156\x61\x6d\x65\163\x3a\x74\x63\x3a\x53\101\x4d\x4c\x3a\62\x2e\60\72\141\x73\x73\x65\162\x74\151\x6f\156", "\163\x61\x6d\x6c\x3a\x41\x74\x74\162\151\x62\165\x74\x65\x56\141\154\x75\x65");
                $i5->appendChild($NK);
                if (!($Hm !== NULL)) {
                    goto Z2;
                }
                $NK->setAttributeNS("\x68\x74\x74\160\72\57\x2f\x77\x77\167\x2e\167\63\56\x6f\162\147\57\62\x30\60\x31\57\x58\115\114\123\x63\x68\x65\155\141\55\x69\x6e\163\x74\x61\156\x63\x65", "\x78\x73\x69\x3a\164\x79\x70\145", $Hm);
                Z2:
                if ($yX instanceof DOMNodeList) {
                    goto TI;
                }
                $NK->appendChild($xx->createTextNode($yX));
                goto Di;
                TI:
                $mp = 0;
                wU:
                if (!($mp < $yX->length)) {
                    goto xh;
                }
                $TV = $xx->importNode($yX->item($mp), TRUE);
                $NK->appendChild($TV);
                to:
                $mp++;
                goto wU;
                xh:
                Di:
                j7:
            }
            tJ:
            $eF = new XMLSecEnc();
            $eF->setNode($xx->documentElement);
            $eF->type = "\150\164\x74\160\72\57\x2f\x77\x77\167\x2e\167\63\56\x6f\162\147\57\x32\x30\60\61\57\x30\64\x2f\x78\x6d\x6c\145\156\143\x23\x45\154\x65\x6d\145\x6e\164";
            $HZ = new XMLSecurityKey(XMLSecurityKey::AES256_CBC);
            $HZ->generateSessionKey();
            $eF->encryptKey($this->encryptionKey, $HZ);
            $HB = $eF->encryptNode($HZ);
            $C3 = $HT->createElementNS("\165\x72\156\x3a\157\x61\x73\151\x73\x3a\156\141\x6d\145\x73\72\x74\143\x3a\123\101\115\x4c\x3a\x32\56\60\x3a\x61\x73\163\145\162\x74\x69\157\x6e", "\163\141\x6d\x6c\x3a\x45\x6e\x63\162\x79\x70\x74\145\x64\x41\x74\x74\162\151\x62\165\164\145");
            $J1->appendChild($C3);
            $C2 = $HT->importNode($HB, TRUE);
            $C3->appendChild($C2);
            Mo:
        }
        qr:
    }
}
