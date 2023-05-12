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
    public function __construct(DOMElement $Z0 = NULL)
    {
        $this->tagName = "\114\157\x67\x6f\165\x74\122\x65\161\165\145\x73\x74";
        $this->id = Utilities::generateID();
        $this->issueInstant = time();
        $this->certificates = array();
        $this->validators = array();
        if (!($Z0 === NULL)) {
            goto BY;
        }
        return;
        BY:
        if ($Z0->hasAttribute("\111\104")) {
            goto Z4;
        }
        throw new Exception("\x4d\151\x73\163\x69\156\147\x20\x49\x44\x20\141\164\164\162\x69\142\x75\164\145\40\157\x6e\x20\123\x41\115\114\x20\x6d\x65\163\x73\141\147\x65\56");
        Z4:
        $this->id = $Z0->getAttribute("\x49\x44");
        if (!($Z0->getAttribute("\x56\x65\x72\163\151\157\x6e") !== "\62\56\60")) {
            goto WT;
        }
        throw new Exception("\125\x6e\x73\x75\160\160\x6f\x72\x74\145\x64\40\x76\x65\162\x73\x69\157\156\72\x20" . $Z0->getAttribute("\x56\145\162\163\151\157\x6e"));
        WT:
        $this->issueInstant = Utilities::xsDateTimeToTimestamp($Z0->getAttribute("\x49\x73\x73\x75\x65\111\x6e\163\164\141\156\x74"));
        if (!$Z0->hasAttribute("\104\145\163\x74\x69\156\141\164\x69\157\x6e")) {
            goto yl;
        }
        $this->destination = $Z0->getAttribute("\104\x65\x73\164\151\156\x61\x74\151\x6f\156");
        yl:
        $YM = Utilities::xpQuery($Z0, "\56\57\x73\x61\155\154\x5f\x61\163\163\x65\162\x74\x69\x6f\156\72\111\163\163\165\x65\x72");
        if (empty($YM)) {
            goto RJ;
        }
        $this->issuer = trim($YM[0]->textContent);
        RJ:
        try {
            $gF = Utilities::validateElement($Z0);
            if (!($gF !== FALSE)) {
                goto D1;
            }
            $this->certificates = $gF["\x43\145\162\164\x69\x66\x69\143\x61\x74\145\163"];
            $this->validators[] = array("\x46\165\156\x63\x74\x69\157\156" => array("\125\x74\151\154\151\164\x69\x65\163", "\x76\x61\154\151\144\x61\164\145\123\151\147\x6e\x61\164\165\162\145"), "\x44\x61\x74\141" => $gF);
            D1:
        } catch (Exception $XU) {
        }
        $this->sessionIndexes = array();
        if (!$Z0->hasAttribute("\x4e\157\164\x4f\x6e\117\162\101\x66\x74\x65\162")) {
            goto RI;
        }
        $this->notOnOrAfter = Utilities::xsDateTimeToTimestamp($Z0->getAttribute("\116\157\164\117\156\x4f\x72\x41\x66\164\x65\x72"));
        RI:
        $Pp = Utilities::xpQuery($Z0, "\56\x2f\x73\141\155\154\x5f\141\x73\163\x65\x72\164\x69\157\x6e\x3a\116\141\x6d\x65\111\x44\x20\174\x20\56\x2f\163\x61\155\x6c\x5f\141\163\163\145\x72\164\151\157\x6e\72\x45\x6e\143\x72\x79\160\x74\x65\x64\111\x44\x2f\170\x65\156\143\x3a\x45\156\143\162\x79\160\x74\x65\144\104\141\x74\x61");
        if (empty($Pp)) {
            goto oS;
        }
        if (count($Pp) > 1) {
            goto Nq;
        }
        goto nr;
        oS:
        throw new Exception("\115\x69\x73\163\x69\156\147\40\74\163\141\x6d\154\72\x4e\141\x6d\x65\x49\x44\x3e\40\x6f\162\40\x3c\x73\141\x6d\154\72\x45\156\143\162\171\160\164\145\144\x49\104\x3e\x20\x69\x6e\40\74\163\141\155\x6c\160\72\114\x6f\x67\x6f\165\164\x52\145\x71\165\145\x73\164\76\56");
        goto nr;
        Nq:
        throw new Exception("\115\x6f\162\x65\x20\x74\x68\141\156\40\157\156\145\x20\x3c\x73\x61\x6d\x6c\x3a\116\x61\155\x65\x49\x44\76\40\157\162\40\74\x73\x61\x6d\x6c\x3a\105\x6e\143\x72\x79\160\164\x65\x64\x44\x3e\x20\151\156\40\x3c\x73\x61\x6d\x6c\x70\x3a\x4c\x6f\147\157\165\x74\122\x65\161\x75\x65\x73\164\x3e\x2e");
        nr:
        $Pp = $Pp[0];
        if ($Pp->localName === "\105\156\x63\x72\171\x70\164\145\144\x44\x61\x74\x61") {
            goto PU;
        }
        $this->nameId = Utilities::parseNameId($Pp);
        goto Vh;
        PU:
        $this->encryptedNameId = $Pp;
        Vh:
        $O8 = Utilities::xpQuery($Z0, "\56\57\163\141\x6d\154\137\160\162\157\x74\x6f\x63\x6f\154\x3a\x53\145\x73\x73\151\x6f\156\111\156\x64\x65\x78");
        foreach ($O8 as $u8) {
            $this->sessionIndexes[] = trim($u8->textContent);
            Rf:
        }
        qJ:
    }
    public function getNotOnOrAfter()
    {
        return $this->notOnOrAfter;
    }
    public function setNotOnOrAfter($jh)
    {
        assert("\x69\163\137\x69\156\x74\x28\x24\x6e\x6f\x74\x4f\x6e\117\162\x41\146\x74\145\162\51\40\x7c\x7c\x20\x69\163\x5f\x6e\165\154\x6c\50\44\156\x6f\164\117\156\117\x72\x41\146\164\145\x72\51");
        $this->notOnOrAfter = $jh;
    }
    public function isNameIdEncrypted()
    {
        if (!($this->encryptedNameId !== NULL)) {
            goto e5;
        }
        return TRUE;
        e5:
        return FALSE;
    }
    public function encryptNameId(XMLSecurityKey $eQ)
    {
        $S9 = new DOMDocument();
        $Jp = $S9->createElement("\162\x6f\x6f\x74");
        $S9->appendChild($Jp);
        SAML2_Utils::addNameId($Jp, $this->nameId);
        $Pp = $Jp->firstChild;
        SAML2_Utils::getContainer()->debugMessage($Pp, "\145\x6e\143\162\171\160\164");
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
            goto B0;
        }
        return;
        B0:
        $Pp = SAML2_Utils::decryptElement($this->encryptedNameId, $eQ, $qo);
        SAML2_Utils::getContainer()->debugMessage($Pp, "\144\145\143\x72\171\160\164");
        $this->nameId = SAML2_Utils::parseNameId($Pp);
        $this->encryptedNameId = NULL;
    }
    public function getNameId()
    {
        if (!($this->encryptedNameId !== NULL)) {
            goto Ju;
        }
        throw new Exception("\101\x74\x74\x65\155\160\164\x65\x64\40\164\157\40\x72\x65\x74\162\151\x65\x76\145\40\145\x6e\x63\x72\171\160\164\145\x64\x20\x4e\x61\155\145\111\104\40\167\151\x74\150\157\165\x74\x20\x64\x65\x63\162\171\x70\164\x69\x6e\147\40\x69\x74\x20\146\x69\x72\163\x74\x2e");
        Ju:
        return $this->nameId;
    }
    public function setNameId($Pp)
    {
        assert("\151\163\137\x61\162\162\141\x79\50\44\156\141\x6d\145\x49\144\x29");
        $this->nameId = $Pp;
    }
    public function getSessionIndexes()
    {
        return $this->sessionIndexes;
    }
    public function setSessionIndexes(array $O8)
    {
        $this->sessionIndexes = $O8;
    }
    public function getSessionIndex()
    {
        if (!empty($this->sessionIndexes)) {
            goto hT;
        }
        return NULL;
        hT:
        return $this->sessionIndexes[0];
    }
    public function setSessionIndex($u8)
    {
        assert("\x69\x73\137\x73\x74\162\151\156\x67\x28\x24\163\145\x73\163\x69\x6f\x6e\111\156\144\145\x78\51\x20\x7c\x7c\x20\x69\x73\137\x6e\x75\154\x6c\x28\x24\163\x65\x73\163\x69\x6f\156\x49\x6e\144\145\x78\x29");
        if (is_null($u8)) {
            goto Dn;
        }
        $this->sessionIndexes = array($u8);
        goto Ec;
        Dn:
        $this->sessionIndexes = array();
        Ec:
    }
    public function getId()
    {
        return $this->id;
    }
    public function setId($kF)
    {
        assert("\x69\x73\137\x73\164\x72\151\x6e\147\x28\x24\151\x64\51");
        $this->id = $kF;
    }
    public function getIssueInstant()
    {
        return $this->issueInstant;
    }
    public function setIssueInstant($XM)
    {
        assert("\x69\x73\137\x69\156\164\50\44\151\163\x73\x75\x65\111\x6e\x73\x74\x61\156\x74\51");
        $this->issueInstant = $XM;
    }
    public function getDestination()
    {
        return $this->destination;
    }
    public function setDestination($v7)
    {
        assert("\x69\163\x5f\163\164\162\x69\156\147\x28\44\x64\x65\163\164\x69\x6e\141\164\151\x6f\156\x29\40\174\x7c\x20\x69\163\137\156\x75\x6c\154\50\x24\144\145\163\164\x69\156\x61\164\151\157\x6e\x29");
        $this->destination = $v7;
    }
    public function getIssuer()
    {
        return $this->issuer;
    }
    public function setIssuer($YM)
    {
        assert("\x69\163\x5f\163\x74\162\x69\156\147\50\44\x69\163\163\165\145\x72\51\x20\x7c\174\40\151\x73\x5f\x6e\165\x6c\154\x28\x24\x69\x73\163\x75\x65\x72\51");
        $this->issuer = $YM;
    }
}
