<?php


namespace Drupal\miniorange_saml;

use DOMElement;
use DOMDocument;
class LogoutRequest
{
    private $tagName;
    private $id;
    private $issuer;
    private $destination;
    private $issueInstant;
    private $certificates;
    private $validators;
    private $notOnOrAfter;
    private $encryptedNameId;
    private $nameId;
    private $sessionIndexes;
    public function __construct(DOMElement $mk = NULL)
    {
        $this->tagName = "\114\157\147\157\165\164\122\145\161\165\x65\163\x74";
        $this->id = Utilities::generateID();
        $this->issueInstant = time();
        $this->certificates = array();
        $this->validators = array();
        if (!($mk === NULL)) {
            goto qx;
        }
        return;
        qx:
        if ($mk->hasAttribute("\111\x44")) {
            goto Gi;
        }
        throw new Exception("\115\151\163\163\x69\156\147\x20\111\104\x20\x61\x74\164\162\151\x62\165\164\145\x20\157\156\x20\x53\x41\x4d\x4c\x20\x6d\x65\x73\163\x61\147\x65\x2e");
        Gi:
        $this->id = $mk->getAttribute("\111\104");
        if (!($mk->getAttribute("\x56\x65\x72\x73\151\157\x6e") !== "\62\56\60")) {
            goto g3;
        }
        throw new Exception("\x55\x6e\163\x75\x70\x70\157\162\x74\145\144\x20\166\145\162\x73\x69\x6f\156\72\40" . $mk->getAttribute("\x56\x65\162\163\x69\157\x6e"));
        g3:
        $this->issueInstant = Utilities::xsDateTimeToTimestamp($mk->getAttribute("\111\163\x73\165\x65\x49\x6e\x73\164\141\x6e\164"));
        if (!$mk->hasAttribute("\x44\145\163\x74\x69\156\141\164\151\157\156")) {
            goto fD;
        }
        $this->destination = $mk->getAttribute("\x44\145\163\164\x69\156\x61\x74\151\x6f\156");
        fD:
        $Ot = Utilities::xpQuery($mk, "\56\x2f\x73\x61\x6d\154\x5f\x61\163\x73\x65\x72\164\151\157\156\x3a\x49\163\163\x75\x65\162");
        if (empty($Ot)) {
            goto fU;
        }
        $this->issuer = trim($Ot[0]->textContent);
        fU:
        try {
            $kk = Utilities::validateElement($mk);
            if (!($kk !== FALSE)) {
                goto sS;
            }
            $this->certificates = $kk["\x43\x65\162\164\151\146\151\143\x61\x74\x65\163"];
            $this->validators[] = array("\x46\165\156\x63\164\x69\157\156" => array("\125\x74\151\154\151\x74\x69\x65\x73", "\166\x61\154\151\x64\x61\164\x65\123\x69\147\156\141\164\x75\162\145"), "\104\141\x74\x61" => $kk);
            sS:
        } catch (Exception $c4) {
        }
        $this->sessionIndexes = array();
        if (!$mk->hasAttribute("\x4e\157\x74\x4f\x6e\x4f\x72\101\146\164\x65\x72")) {
            goto z4;
        }
        $this->notOnOrAfter = Utilities::xsDateTimeToTimestamp($mk->getAttribute("\116\x6f\164\x4f\x6e\x4f\162\101\146\x74\x65\x72"));
        z4:
        $Sj = Utilities::xpQuery($mk, "\x2e\x2f\x73\141\155\x6c\x5f\141\163\x73\x65\162\164\x69\157\156\72\116\x61\155\x65\x49\x44\x20\x7c\40\56\x2f\163\141\x6d\x6c\137\141\163\x73\x65\162\164\151\x6f\156\72\105\x6e\x63\x72\171\x70\x74\145\144\111\x44\57\170\x65\x6e\x63\x3a\x45\156\143\162\171\x70\164\145\x64\104\x61\164\x61");
        if (empty($Sj)) {
            goto xQ;
        }
        if (count($Sj) > 1) {
            goto AP;
        }
        goto cE;
        xQ:
        throw new Exception("\115\151\x73\x73\151\156\x67\x20\x3c\163\x61\155\154\72\116\141\x6d\145\111\x44\76\40\157\162\x20\x3c\163\x61\155\154\x3a\x45\156\143\x72\171\x70\164\145\x64\111\x44\x3e\x20\151\x6e\40\74\163\x61\155\x6c\x70\72\114\157\x67\x6f\x75\164\x52\145\x71\165\145\x73\164\76\56");
        goto cE;
        AP:
        throw new Exception("\115\157\x72\x65\40\164\150\x61\x6e\40\157\x6e\145\x20\74\163\x61\155\x6c\x3a\x4e\141\155\145\111\x44\76\40\157\x72\40\x3c\163\x61\x6d\x6c\72\x45\x6e\143\x72\171\x70\x74\x65\x64\x44\x3e\x20\x69\156\x20\74\x73\141\x6d\x6c\x70\x3a\114\157\147\x6f\x75\x74\122\x65\x71\x75\x65\x73\x74\76\x2e");
        cE:
        $Sj = $Sj[0];
        if ($Sj->localName === "\105\x6e\x63\x72\x79\x70\164\145\144\104\x61\x74\x61") {
            goto VE;
        }
        $this->nameId = Utilities::parseNameId($Sj);
        goto LI;
        VE:
        $this->encryptedNameId = $Sj;
        LI:
        $O4 = Utilities::xpQuery($mk, "\x2e\57\x73\141\155\x6c\x5f\160\162\157\x74\x6f\x63\x6f\154\x3a\x53\x65\x73\x73\151\157\156\111\156\144\145\170");
        foreach ($O4 as $mT) {
            $this->sessionIndexes[] = trim($mT->textContent);
            DT:
        }
        Lv:
    }
    public function getNotOnOrAfter()
    {
        return $this->notOnOrAfter;
    }
    public function setNotOnOrAfter($Xg)
    {
        assert("\x69\x73\x5f\x69\156\x74\x28\44\156\157\164\117\156\117\162\x41\x66\164\x65\x72\51\40\x7c\x7c\40\x69\x73\137\156\x75\154\154\x28\x24\x6e\157\x74\117\156\117\x72\x41\x66\x74\x65\x72\x29");
        $this->notOnOrAfter = $Xg;
    }
    public function isNameIdEncrypted()
    {
        if (!($this->encryptedNameId !== NULL)) {
            goto xh;
        }
        return TRUE;
        xh:
        return FALSE;
    }
    public function encryptNameId(XMLSecurityKey $yQ)
    {
        $NW = new DOMDocument();
        $wp = $NW->createElement("\x72\157\157\x74");
        $NW->appendChild($wp);
        SAML2_Utils::addNameId($wp, $this->nameId);
        $Sj = $wp->firstChild;
        SAML2_Utils::getContainer()->debugMessage($Sj, "\x65\x6e\x63\162\x79\160\x74");
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
            goto ti;
        }
        return;
        ti:
        $Sj = SAML2_Utils::decryptElement($this->encryptedNameId, $yQ, $ce);
        SAML2_Utils::getContainer()->debugMessage($Sj, "\x64\145\x63\162\x79\160\164");
        $this->nameId = SAML2_Utils::parseNameId($Sj);
        $this->encryptedNameId = NULL;
    }
    public function getNameId()
    {
        if (!($this->encryptedNameId !== NULL)) {
            goto LP;
        }
        throw new Exception("\101\x74\x74\145\x6d\160\x74\145\x64\x20\x74\x6f\40\162\x65\164\162\151\145\x76\145\40\145\156\143\x72\x79\160\164\x65\x64\x20\x4e\x61\x6d\145\x49\104\40\x77\151\164\150\x6f\x75\x74\40\x64\145\143\x72\x79\160\x74\x69\156\x67\x20\x69\164\40\x66\151\162\163\164\56");
        LP:
        return $this->nameId;
    }
    public function setNameId($Sj)
    {
        assert("\151\x73\137\x61\162\162\141\171\50\44\x6e\x61\x6d\145\111\x64\x29");
        $this->nameId = $Sj;
    }
    public function getSessionIndexes()
    {
        return $this->sessionIndexes;
    }
    public function setSessionIndexes(array $O4)
    {
        $this->sessionIndexes = $O4;
    }
    public function getSessionIndex()
    {
        if (!empty($this->sessionIndexes)) {
            goto K6;
        }
        return NULL;
        K6:
        return $this->sessionIndexes[0];
    }
    public function setSessionIndex($mT)
    {
        assert("\151\163\137\163\164\162\151\156\147\50\44\x73\145\x73\163\x69\157\156\x49\156\x64\145\170\51\x20\x7c\x7c\x20\151\163\137\156\165\x6c\x6c\x28\44\x73\x65\163\x73\x69\x6f\x6e\x49\156\144\145\170\x29");
        if (is_null($mT)) {
            goto cn;
        }
        $this->sessionIndexes = array($mT);
        goto DV;
        cn:
        $this->sessionIndexes = array();
        DV:
    }
    public function getId()
    {
        return $this->id;
    }
    public function setId($MF)
    {
        assert("\151\163\x5f\x73\x74\162\151\x6e\147\50\x24\151\x64\x29");
        $this->id = $MF;
    }
    public function getIssueInstant()
    {
        return $this->issueInstant;
    }
    public function setIssueInstant($OU)
    {
        assert("\x69\x73\x5f\151\156\164\50\44\x69\x73\163\x75\145\111\156\163\x74\x61\156\164\x29");
        $this->issueInstant = $OU;
    }
    public function getDestination()
    {
        return $this->destination;
    }
    public function setDestination($IQ)
    {
        assert("\151\x73\x5f\163\x74\x72\x69\156\147\x28\x24\144\x65\163\x74\x69\156\141\164\151\157\156\x29\40\x7c\x7c\40\151\x73\137\x6e\165\154\x6c\x28\44\x64\x65\163\x74\x69\x6e\141\x74\x69\157\156\x29");
        $this->destination = $IQ;
    }
    public function getIssuer()
    {
        return $this->issuer;
    }
    public function setIssuer($Ot)
    {
        assert("\151\163\x5f\x73\164\x72\x69\x6e\x67\50\44\x69\163\163\165\x65\x72\x29\40\x7c\174\x20\x69\163\137\156\x75\154\x6c\50\x24\x69\x73\x73\165\x65\x72\x29");
        $this->issuer = $Ot;
    }
}
