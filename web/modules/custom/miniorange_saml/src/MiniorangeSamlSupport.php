<?php


namespace Drupal\miniorange_saml;

use Drupal\miniorange_saml\MiniorangeSAMLConstants;
use GuzzleHttp\Exception\RequestException;
class MiniorangeSamlSupport
{
    public $email;
    public $phone;
    public $query;
    public $query_type;
    public function __construct($S_, $vT, $bD, $XE)
    {
        $this->email = $S_;
        $this->phone = $vT;
        $this->query = $bD;
        $this->query_type = $XE;
    }
    public function sendSupportQuery()
    {
        $yI = \Drupal::service("\x65\170\164\x65\x6e\163\x69\x6f\156\56\154\x69\x73\164\56\155\157\x64\165\154\x65")->getExtensionInfo("\155\151\156\x69\x6f\x72\x61\156\x67\145\137\163\141\x6d\x6c");
        $um = $yI["\166\x65\x72\x73\151\157\156"];
        $Nv = phpversion();
        $aa = $this->query_type === "\x4e\x65\x77\x20\106\x65\141\x74\x75\x72\145\40\122\145\161\165\x65\x73\164" ? "\x28\116\145\167\x20\x46\145\141\164\165\162\x65\x20\x52\x65\x71\x75\x65\163\x74\x29" : '';
        $this->query = "\133\x44\x72\165\160\141\x6c\40" . Utilities::mo_get_drupal_core_version() . "\x20\123\x41\x4d\114\x20\x53\120\x20" . ucfirst(strtolower(MiniorangeSAMLConstants::PLUGIN_VERSION)) . "\x20" . $aa . "\40\174\40" . $um . "\40\x7c\x20\x50\x48\x50\40" . $Nv . "\x20\x5d\40" . $this->query;
        $HL = array("\143\x6f\155\x70\141\x6e\171" => $_SERVER["\123\x45\122\126\105\122\137\116\101\115\x45"], "\145\155\x61\151\x6c" => $this->email, "\x63\x63\105\x6d\x61\151\154" => "\144\162\165\160\x61\154\163\x75\x70\160\x6f\162\164\100\170\x65\143\165\x72\x69\146\x79\x2e\143\x6f\x6d", "\160\150\157\x6e\145" => $this->query_type != "\x44\145\x6d\x6f\x20\122\x65\161\165\x65\x73\164" ? $this->phone : '', "\x71\165\145\162\171" => $this->query);
        $b1 = json_encode($HL);
        $nD = MiniorangeSAMLConstants::BASE_URL . "\x2f\x6d\x6f\141\x73\x2f\x72\x65\x73\x74\57\x63\165\x73\x74\x6f\155\x65\x72\57\x63\x6f\156\x74\141\143\x74\x2d\165\x73";
        try {
            $DI = \Drupal::httpClient()->request("\x50\x4f\123\x54", $nD, ["\x62\x6f\144\x79" => $b1, "\141\154\x6c\x6f\x77\x5f\x72\145\x64\x69\162\x65\x63\x74\x73" => TRUE, "\150\164\x74\160\x5f\x65\162\162\x6f\162\163" => FALSE, "\144\x65\143\x6f\x64\x65\137\x63\x6f\156\164\145\156\164" => true, "\x76\x65\162\151\x66\x79" => FALSE, "\150\145\141\x64\x65\x72\x73" => array("\x43\157\x6e\x74\145\156\164\x2d\x54\171\160\x65" => "\141\160\x70\x6c\151\143\x61\164\151\157\156\x2f\152\163\157\156", "\x41\x75\x74\x68\157\162\151\x7a\141\x74\151\157\156" => "\102\x61\163\151\x63")]);
        } catch (RequestException $kn) {
            \Drupal::logger("\155\151\156\151\x6f\162\x61\156\x67\145\137\x73\x61\x6d\x6c")->notice("\105\162\x72\157\x72\40\141\164\x20\x25\155\x65\164\x68\x6f\x64\x20\x6f\146\40\x25\x66\x69\x6c\x65\72\x20\45\x65\162\x72\x6f\162", array("\45\x6d\145\164\x68\x6f\144" => "\x73\145\156\144\123\x75\160\160\157\162\x74\x51\x75\145\162\171", "\x25\146\x69\154\x65" => "\x4d\151\x6e\151\x6f\x72\x61\156\x67\x65\x53\x41\115\x4c\123\165\x70\160\157\162\164\x2e\x70\x68\160", "\x25\x65\x72\162\157\162" => $kn->getMessage()));
            return false;
        }
        return true;
    }
}
