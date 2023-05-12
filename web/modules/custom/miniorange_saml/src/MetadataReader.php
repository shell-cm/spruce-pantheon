<?php


namespace Drupal\miniorange_saml;

class MetadataReader
{
    private $identityProviders;
    private $serviceProviders;
    public function __construct(\DOMNode $Z0 = NULL)
    {
        $this->identityProviders = array();
        $this->serviceProviders = array();
        $GL = Utilities::xpQuery($Z0, "\56\57\x73\141\x6d\154\137\155\145\x74\x61\x64\x61\164\141\x3a\105\156\164\x69\x74\x79\104\145\x73\x63\x72\151\x70\164\157\162");
        foreach ($GL as $dE) {
            $ZB = Utilities::xpQuery($dE, "\56\x2f\163\141\x6d\154\137\x6d\x65\x74\141\x64\x61\x74\141\72\111\x44\x50\123\123\x4f\x44\x65\x73\x63\x72\x69\160\x74\157\162");
            if (!(isset($ZB) && !empty($ZB))) {
                goto ZZ;
            }
            array_push($this->identityProviders, new IdentityProviders($dE));
            ZZ:
            E1:
        }
        SM:
    }
    public function getIdentityProviders()
    {
        return $this->identityProviders;
    }
    public function getServiceProviders()
    {
        return $this->serviceProviders;
    }
}
class IdentityProviders
{
    private $idpName;
    private $entityID;
    private $loginDetails;
    private $logoutDetails;
    private $signingCertificate;
    private $encryptionCertificate;
    private $signedRequest;
    public function __construct(\DOMElement $Z0 = NULL)
    {
        $this->idpName = '';
        $this->loginDetails = array();
        $this->logoutDetails = array();
        $this->signingCertificate = array();
        $this->encryptionCertificate = array();
        if (!$Z0->hasAttribute("\145\156\164\151\164\171\x49\x44")) {
            goto yO;
        }
        $this->entityID = $Z0->getAttribute("\145\156\x74\x69\164\171\x49\104");
        yO:
        if (!$Z0->hasAttribute("\x57\x61\156\164\101\x75\164\x68\156\x52\145\x71\165\145\163\164\x73\x53\151\x67\156\145\144")) {
            goto am;
        }
        $this->signedRequest = $Z0->getAttribute("\127\x61\x6e\164\101\x75\x74\x68\x6e\122\145\x71\165\145\163\164\163\x53\151\x67\x6e\145\x64");
        am:
        $ZB = Utilities::xpQuery($Z0, "\56\x2f\163\141\155\154\137\155\x65\x74\141\x64\141\164\141\x3a\111\104\120\x53\x53\117\x44\x65\x73\143\x72\x69\x70\x74\157\x72");
        if (count($ZB) > 1) {
            goto X6;
        }
        if (empty($ZB)) {
            goto be;
        }
        goto vs;
        X6:
        throw new Exception("\115\157\x72\x65\x20\x74\150\141\156\40\x6f\x6e\x65\40\74\111\104\x50\123\x53\117\x44\x65\x73\x63\162\x69\x70\x74\157\162\76\40\x69\156\x20\x3c\x45\156\164\151\x74\171\x44\145\163\x63\162\x69\160\x74\x6f\162\76\x2e");
        goto vs;
        be:
        throw new Exception("\115\x69\163\x73\x69\156\x67\x20\162\x65\161\165\151\x72\x65\x64\x20\74\x49\x44\120\x53\123\x4f\104\145\163\x63\162\x69\x70\x74\157\x72\76\40\151\x6e\40\x3c\105\156\164\151\164\171\104\145\x73\x63\162\151\160\x74\x6f\162\x3e\x2e");
        vs:
        $fa = $ZB[0];
        $VU = Utilities::xpQuery($Z0, "\56\x2f\163\141\x6d\x6c\x5f\x6d\145\x74\x61\x64\x61\x74\141\x3a\105\x78\x74\145\156\163\x69\157\x6e\163");
        if (!$VU) {
            goto I6;
        }
        $this->parseInfo($fa);
        I6:
        $this->parseSSOService($fa);
        $this->parseSLOService($fa);
        $this->parsex509Certificate($fa);
    }
    private function parseInfo($Z0)
    {
        $VO = Utilities::xpQuery($Z0, "\x2e\x2f\x6d\x64\165\x69\72\x55\x49\111\x6e\x66\x6f\57\x6d\x64\x75\151\72\x44\151\163\160\154\141\171\x4e\141\x6d\145");
        foreach ($VO as $Fg) {
            if (!($Fg->hasAttribute("\x78\155\154\72\154\x61\156\147") && $Fg->getAttribute("\x78\155\154\72\x6c\x61\x6e\147") == "\x65\156")) {
                goto OX;
            }
            $this->idpName = $Fg->textContent;
            OX:
            Bq:
        }
        BN:
    }
    private function parseSSOService($Z0)
    {
        $ou = Utilities::xpQuery($Z0, "\56\57\x73\x61\x6d\154\137\x6d\145\164\141\x64\x61\x74\141\x3a\x53\x69\156\x67\x6c\x65\x53\x69\147\156\117\x6e\x53\x65\162\x76\x69\x63\x65");
        foreach ($ou as $sv) {
            $w_ = str_replace("\x75\162\x6e\x3a\157\141\163\151\x73\x3a\x6e\141\155\145\163\72\x74\143\x3a\x53\x41\x4d\x4c\x3a\x32\x2e\x30\72\142\151\x6e\x64\x69\x6e\147\x73\x3a", '', $sv->getAttribute("\x42\x69\156\144\x69\x6e\147"));
            $this->loginDetails = array_merge($this->loginDetails, array($w_ => $sv->getAttribute("\x4c\157\x63\x61\164\x69\x6f\156")));
            th:
        }
        pP:
    }
    private function parseSLOService($Z0)
    {
        $GZ = Utilities::xpQuery($Z0, "\56\x2f\x73\141\x6d\154\x5f\x6d\145\164\x61\144\141\164\x61\x3a\123\x69\x6e\147\154\x65\x4c\x6f\147\x6f\165\164\x53\145\162\x76\151\143\x65");
        foreach ($GZ as $cS) {
            $w_ = str_replace("\x75\162\x6e\x3a\x6f\x61\163\x69\163\x3a\x6e\x61\x6d\x65\163\72\164\x63\x3a\x53\101\x4d\x4c\x3a\62\56\60\x3a\x62\x69\156\144\151\156\147\163\x3a", '', $cS->getAttribute("\102\151\x6e\x64\x69\x6e\x67"));
            $this->logoutDetails = array_merge($this->logoutDetails, array($w_ => $cS->getAttribute("\x4c\157\143\141\x74\x69\157\x6e")));
            hb:
        }
        oC:
    }
    private function parsex509Certificate($Z0)
    {
        foreach (Utilities::xpQuery($Z0, "\x2e\x2f\163\x61\155\x6c\137\155\x65\x74\x61\x64\x61\164\x61\x3a\x4b\145\171\x44\145\x73\143\162\151\160\164\x6f\x72") as $Fk) {
            if ($Fk->hasAttribute("\x75\x73\145")) {
                goto c0;
            }
            $this->parseSigningCertificate($Fk);
            goto U2;
            c0:
            if ($Fk->getAttribute("\165\163\x65") == "\x65\156\x63\162\x79\160\x74\x69\157\156") {
                goto er;
            }
            $this->parseSigningCertificate($Fk);
            goto TB;
            er:
            $this->parseEncryptionCertificate($Fk);
            TB:
            U2:
            Eg:
        }
        C4:
    }
    private function parseSigningCertificate($Z0)
    {
        $A0 = Utilities::xpQuery($Z0, "\56\x2f\144\163\72\113\x65\x79\x49\156\146\x6f\x2f\x64\163\72\x58\x35\x30\71\104\x61\x74\x61\57\x64\163\72\x58\x35\60\71\x43\x65\162\164\x69\146\x69\x63\141\x74\145");
        $z1 = trim($A0[0]->textContent);
        $z1 = str_replace(array("\xd", "\12", "\11", "\x20"), '', $z1);
        if (empty($A0)) {
            goto kW;
        }
        array_push($this->signingCertificate, Utilities::sanitize_certificate($z1));
        kW:
    }
    private function parseEncryptionCertificate($Z0)
    {
        $A0 = Utilities::xpQuery($Z0, "\x2e\x2f\x64\x73\x3a\x4b\145\171\111\x6e\146\157\57\144\163\x3a\x58\65\60\71\x44\x61\x74\x61\57\x64\x73\x3a\x58\x35\x30\71\103\x65\162\164\151\146\x69\143\141\164\145");
        $z1 = trim($A0[0]->textContent);
        $z1 = str_replace(array("\15", "\xa", "\x9", "\x20"), '', $z1);
        if (empty($A0)) {
            goto X7;
        }
        array_push($this->encryptionCertificate, $z1);
        X7:
    }
    public function getIdpName()
    {
        return '';
    }
    public function getEntityID()
    {
        return $this->entityID;
    }
    public function getLoginURL($w_)
    {
        return $this->loginDetails[$w_];
    }
    public function getLogoutURL($w_)
    {
        return isset($this->logoutDetails[$w_]) ? $this->logoutDetails[$w_] : '';
    }
    public function getLoginDetails()
    {
        return $this->loginDetails;
    }
    public function getLogoutDetails()
    {
        return $this->logoutDetails;
    }
    public function getSigningCertificate()
    {
        return $this->signingCertificate;
    }
    public function getEncryptionCertificate()
    {
        return $this->encryptionCertificate[0];
    }
    public function isRequestSigned()
    {
        return $this->signedRequest;
    }
}
class ServiceProviders
{
}
