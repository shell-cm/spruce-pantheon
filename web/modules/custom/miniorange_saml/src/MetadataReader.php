<?php


namespace Drupal\miniorange_saml;

class MetadataReader
{
    private $identityProviders;
    private $serviceProviders;
    public function __construct(\DOMNode $mk = NULL)
    {
        $this->identityProviders = array();
        $this->serviceProviders = array();
        $IH = Utilities::xpQuery($mk, "\56\57\x73\x61\x6d\x6c\137\155\145\x74\x61\x64\x61\x74\x61\x3a\105\x6e\164\x69\x74\171\104\145\x73\143\162\151\160\164\x6f\162");
        foreach ($IH as $Wc) {
            $g7 = Utilities::xpQuery($Wc, "\x2e\x2f\x73\x61\x6d\x6c\137\155\145\x74\x61\144\141\164\x61\72\111\x44\x50\x53\123\x4f\x44\145\x73\x63\162\x69\160\x74\157\x72");
            if (!(isset($g7) && !empty($g7))) {
                goto gQ;
            }
            array_push($this->identityProviders, new IdentityProviders($Wc));
            gQ:
            LC:
        }
        vf:
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
    public function __construct(\DOMElement $mk = NULL)
    {
        $this->idpName = '';
        $this->loginDetails = array();
        $this->logoutDetails = array();
        $this->signingCertificate = array();
        $this->encryptionCertificate = array();
        if (!$mk->hasAttribute("\x65\156\164\151\x74\x79\111\x44")) {
            goto uu;
        }
        $this->entityID = $mk->getAttribute("\x65\156\x74\x69\164\171\x49\x44");
        uu:
        if (!$mk->hasAttribute("\127\141\x6e\x74\101\165\164\x68\156\122\x65\x71\165\145\163\164\163\x53\151\147\x6e\145\144")) {
            goto dn;
        }
        $this->signedRequest = $mk->getAttribute("\x57\141\156\164\x41\x75\164\x68\x6e\122\x65\161\165\145\x73\x74\163\x53\151\147\156\145\144");
        dn:
        $g7 = Utilities::xpQuery($mk, "\56\57\x73\x61\x6d\154\137\155\x65\164\141\144\x61\164\141\x3a\111\104\x50\x53\x53\117\x44\x65\x73\143\x72\151\160\164\x6f\162");
        if (count($g7) > 1) {
            goto fL;
        }
        if (empty($g7)) {
            goto MI;
        }
        goto ss;
        fL:
        throw new Exception("\115\157\x72\x65\40\164\150\x61\x6e\x20\x6f\156\145\40\74\111\104\x50\123\123\x4f\104\145\163\143\162\151\x70\164\x6f\x72\x3e\40\151\x6e\x20\x3c\x45\x6e\164\151\164\171\x44\145\x73\143\x72\151\x70\x74\x6f\x72\76\56");
        goto ss;
        MI:
        throw new Exception("\x4d\151\x73\x73\x69\x6e\x67\x20\x72\145\161\165\151\162\x65\x64\40\x3c\x49\x44\x50\x53\123\x4f\104\x65\x73\x63\162\151\x70\x74\x6f\x72\76\x20\x69\156\40\74\105\156\x74\x69\x74\171\x44\145\x73\x63\162\x69\x70\164\157\162\76\x2e");
        ss:
        $wD = $g7[0];
        $RI = Utilities::xpQuery($mk, "\x2e\57\163\x61\x6d\x6c\137\x6d\145\164\x61\x64\x61\x74\141\72\x45\170\164\x65\156\163\151\x6f\x6e\163");
        if (!$RI) {
            goto nw;
        }
        $this->parseInfo($wD);
        nw:
        $this->parseSSOService($wD);
        $this->parseSLOService($wD);
        $this->parsex509Certificate($wD);
    }
    private function parseInfo($mk)
    {
        $QK = Utilities::xpQuery($mk, "\x2e\x2f\x6d\144\x75\151\x3a\x55\111\x49\x6e\146\x6f\57\155\144\x75\151\72\104\x69\163\160\154\141\171\116\x61\x6d\x65");
        foreach ($QK as $KC) {
            if (!($KC->hasAttribute("\x78\x6d\154\x3a\154\141\x6e\147") && $KC->getAttribute("\170\155\x6c\72\154\x61\156\147") == "\145\156")) {
                goto DB;
            }
            $this->idpName = $KC->textContent;
            DB:
            u1:
        }
        gc:
    }
    private function parseSSOService($mk)
    {
        $zb = Utilities::xpQuery($mk, "\x2e\x2f\x73\141\x6d\x6c\x5f\155\x65\164\141\x64\141\164\x61\x3a\x53\151\x6e\147\x6c\145\123\x69\147\156\117\156\123\145\162\x76\x69\x63\x65");
        foreach ($zb as $wI) {
            $ao = str_replace("\165\162\x6e\x3a\157\141\163\151\163\72\156\141\155\x65\163\x3a\164\x63\x3a\x53\101\x4d\114\72\62\56\60\x3a\142\151\156\x64\151\x6e\x67\x73\x3a", '', $wI->getAttribute("\102\x69\156\x64\x69\156\147"));
            $this->loginDetails = array_merge($this->loginDetails, array($ao => $wI->getAttribute("\x4c\x6f\143\141\x74\151\x6f\156")));
            av:
        }
        AA:
    }
    private function parseSLOService($mk)
    {
        $KX = Utilities::xpQuery($mk, "\x2e\57\x73\x61\x6d\x6c\x5f\155\145\164\141\144\x61\164\x61\x3a\123\151\156\147\154\145\114\x6f\x67\x6f\x75\x74\123\x65\x72\x76\x69\143\x65");
        foreach ($KX as $kW) {
            $ao = str_replace("\x75\x72\x6e\x3a\x6f\141\x73\151\163\72\156\x61\x6d\145\163\x3a\164\143\72\x53\101\115\114\x3a\62\x2e\60\72\142\x69\x6e\144\x69\x6e\147\x73\72", '', $kW->getAttribute("\102\x69\x6e\x64\151\x6e\x67"));
            $this->logoutDetails = array_merge($this->logoutDetails, array($ao => $kW->getAttribute("\114\157\143\x61\164\151\157\156")));
            ov:
        }
        q5:
    }
    private function parsex509Certificate($mk)
    {
        foreach (Utilities::xpQuery($mk, "\x2e\x2f\x73\141\x6d\x6c\x5f\x6d\x65\x74\x61\x64\141\164\141\72\x4b\x65\x79\x44\x65\x73\x63\162\x69\x70\164\x6f\162") as $y3) {
            if ($y3->hasAttribute("\165\163\145")) {
                goto tD;
            }
            $this->parseSigningCertificate($y3);
            goto Pd;
            tD:
            if ($y3->getAttribute("\x75\163\x65") == "\x65\x6e\143\x72\171\160\x74\x69\x6f\x6e") {
                goto RP;
            }
            $this->parseSigningCertificate($y3);
            goto Td;
            RP:
            $this->parseEncryptionCertificate($y3);
            Td:
            Pd:
            Kh:
        }
        tl:
    }
    private function parseSigningCertificate($mk)
    {
        $Jn = Utilities::xpQuery($mk, "\56\x2f\x64\x73\x3a\113\145\x79\111\156\x66\x6f\x2f\x64\x73\x3a\x58\65\x30\x39\104\141\x74\141\x2f\144\x73\72\x58\65\x30\x39\x43\x65\162\164\151\146\151\x63\x61\164\145");
        $T8 = trim($Jn[0]->textContent);
        $T8 = str_replace(array("\xd", "\12", "\11", "\x20"), '', $T8);
        if (empty($Jn)) {
            goto nW;
        }
        array_push($this->signingCertificate, Utilities::sanitize_certificate($T8));
        nW:
    }
    private function parseEncryptionCertificate($mk)
    {
        $Jn = Utilities::xpQuery($mk, "\x2e\x2f\144\163\x3a\113\145\171\x49\156\146\157\57\x64\163\x3a\x58\x35\60\x39\x44\x61\164\x61\x2f\x64\x73\72\130\x35\x30\71\103\x65\x72\164\x69\146\x69\143\141\164\x65");
        $T8 = trim($Jn[0]->textContent);
        $T8 = str_replace(array("\15", "\xa", "\x9", "\40"), '', $T8);
        if (empty($Jn)) {
            goto Le;
        }
        array_push($this->encryptionCertificate, $T8);
        Le:
    }
    public function getIdpName()
    {
        return '';
    }
    public function getEntityID()
    {
        return $this->entityID;
    }
    public function getLoginURL($ao)
    {
        return $this->loginDetails[$ao];
    }
    public function getLogoutURL($ao)
    {
        return isset($this->logoutDetails[$ao]) ? $this->logoutDetails[$ao] : '';
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
