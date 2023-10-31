<?php


namespace Drupal\miniorange_saml\Form;

use Drupal\Core\Ajax\AjaxResponse;
use Drupal\Core\Ajax\OpenModalDialogCommand;
use Drupal\Core\Ajax\ReplaceCommand;
use Drupal\Core\Form\FormBase;
use Drupal\miniorange_saml\MiniorangeSAMLConstants;
use Drupal\miniorange_saml\Utilities;
use Drupal\Core\Form\FormStateInterface;
class MiniorangeSupport extends FormBase
{
    public function getFormId()
    {
        return "\155\x69\x6e\151\157\x72\x61\156\x67\145\x5f\163\x61\x6d\x6c\x5f\163\x70\x5f\163\165\160\160\157\162\x74";
    }
    public function buildForm(array $form, FormStateInterface $form_state)
    {
        $f5 = \Drupal::config("\x6d\151\156\x69\x6f\x72\x61\x6e\147\145\x5f\163\141\x6d\154\x2e\x73\145\x74\x74\x69\x6e\x67\x73");
        $vd = $f5->get("\x6d\151\156\151\157\x72\x61\156\x67\145\x5f\x73\141\x6d\x6c\137\143\165\163\164\157\x6d\x65\x72\x5f\x61\x64\x6d\x69\156\137\145\x6d\141\x69\x6c");
        $YV = $f5->get("\x6d\x69\x6e\151\x6f\162\141\x6e\x67\145\x5f\x73\141\x6d\154\x5f\143\x75\163\x74\x6f\155\x65\x72\x5f\x61\x64\x6d\151\156\x5f\160\150\157\156\145");
        $form["\155\141\162\x6b\x75\x70\x5f\146\x69\x72\163\164"] = array("\43\141\164\x74\141\x63\150\145\144" => array("\x6c\151\x62\x72\141\162\x79" => array("\155\x69\156\151\157\162\x61\156\147\145\x5f\163\x61\155\x6c\x2f\155\x69\156\x69\157\x72\x61\156\x67\145\137\163\141\155\154\56\x61\144\155\151\x6e")));
        $form["\x6d\151\156\x69\x6f\162\x61\x6e\147\145\x5f\x73\x61\155\154\137\x73\x75\x70\x70\157\162\x74"] = array("\43\x74\x79\x70\145" => "\x63\157\x6e\x74\x61\151\x6e\145\162", "\x23\x70\x72\145\146\151\170" => "\74\144\x69\x76\40\151\144\75\42\x6d\x6f\144\x61\x6c\137\x73\x75\x70\x70\157\x72\164\x5f\x66\157\162\155\x22\x3e", "\43\x73\165\x66\x66\151\x78" => "\x3c\57\144\x69\x76\x3e");
        $form["\x6d\x69\156\x69\157\x72\141\x6e\x67\145\137\163\141\x6d\x6c\137\x73\x75\x70\160\157\162\x74"]["\x6d\157\137\x6f\164\x70\x5f\x76\145\x72\151\146\151\143\x61\x74\151\157\156\137\x73\x63\x72\151\160\164"] = array("\43\x61\164\164\141\x63\x68\145\x64" => array("\154\151\x62\x72\141\x72\171" => array("\143\x6f\x72\145\57\x64\162\x75\160\x61\x6c\x2e\x64\x69\141\x6c\x6f\x67\56\x61\x6a\141\170", "\155\x69\156\151\157\162\141\x6e\147\x65\x5f\163\141\x6d\154\57\x6d\x69\156\151\157\x72\x61\x6e\x67\145\x5f\x73\x61\x6d\154\x2e\x61\144\x6d\151\x6e")));
        $form["\x6d\x69\156\151\157\x72\141\156\x67\145\x5f\163\141\x6d\154\137\x73\x75\x70\160\x6f\162\164"]["\155\x6f\137\x6f\x74\x70\137\x76\145\162\x69\x66\x69\143\x61\164\151\x6f\x6e\x5f\x73\164\141\x74\x75\163\x5f\155\x65\163\x73\x61\147\x65\x73"] = array("\x23\164\x79\160\145" => "\x73\x74\141\164\165\x73\137\155\x65\x73\163\141\147\x65\163", "\x23\x77\x65\x69\147\150\x74" => -10);
        $form["\155\151\156\151\x6f\x72\141\156\147\x65\x5f\163\141\x6d\x6c\x5f\163\165\160\x70\x6f\162\164"]["\155\x6f\137\x73\x61\x6d\154\137\155\x61\162\153\x75\x70\x5f\x31"] = array("\x23\x6d\x61\162\x6b\x75\160" => t("\74\x70\x20\143\154\141\x73\163\75\x22\155\157\137\x73\141\155\154\x5f\150\x69\x67\x68\154\151\x67\x68\x74\x5f\x62\141\143\153\147\x72\157\165\x6e\144\x5f\x6e\157\164\145\42\76\12\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\40\40\x20\40\x20\x20\x20\40\40\116\145\145\x64\40\x61\x6e\171\40\150\x65\154\160\77\40\x4a\165\x73\x74\x20\x73\145\x6e\x64\x20\165\163\40\x61\40\161\165\x65\162\x79\x20\x61\156\144\x20\x77\x65\x20\167\151\154\154\40\x67\x65\164\x20\x62\141\143\153\x20\164\157\x20\x79\x6f\x75\x20\x73\157\157\156\56\74\57\160\x3e"));
        $form["\x6d\x69\x6e\151\x6f\162\141\x6e\x67\x65\137\x73\x61\155\x6c\137\163\165\x70\x70\x6f\162\x74"]["\x6d\x6f\137\163\141\x6d\154\137\163\165\x70\x70\157\162\x74\x5f\x65\x6d\x61\151\x6c\137\x61\x64\144\162\145\163\x73"] = array("\43\x74\171\x70\145" => "\145\x6d\x61\151\x6c", "\x23\x74\151\x74\154\145" => $this->t("\105\155\x61\151\154"), "\43\144\x65\x66\x61\x75\x6c\x74\x5f\x76\x61\154\165\x65" => $vd, "\43\x72\x65\x71\x75\151\x72\145\x64" => true, "\x23\x61\x74\164\x72\151\x62\x75\x74\145\x73" => array("\x70\x6c\x61\x63\145\x68\x6f\154\x64\145\x72" => t("\x45\156\164\x65\162\40\x79\157\165\162\40\145\155\141\x69\154"), "\x73\x74\171\x6c\145" => "\167\x69\144\164\x68\72\x39\x39\x25\73\155\141\x72\x67\151\x6e\55\142\x6f\164\x74\x6f\155\x3a\61\x25\73"));
        $form["\x6d\x69\x6e\151\157\162\141\156\147\x65\x5f\x73\x61\155\x6c\137\x73\165\160\160\x6f\x72\x74"]["\155\157\137\x73\x61\x6d\154\x5f\x73\x75\160\160\157\x72\164\x5f\160\x68\x6f\156\145\x5f\x6e\165\x6d\x62\145\162"] = array("\x23\x74\171\x70\x65" => "\164\145\x78\x74\x66\x69\145\154\x64", "\43\164\151\164\154\x65" => t("\x50\x68\x6f\156\145"), "\x23\x64\145\146\x61\x75\x6c\x74\137\x76\141\x6c\x75\145" => $YV, "\x23\141\164\x74\x72\151\142\x75\164\x65\x73" => array("\x70\x6c\141\x63\145\150\x6f\x6c\x64\x65\x72" => $this->t("\105\x6e\x74\x65\x72\40\156\165\155\142\145\162\x20\x77\151\x74\150\40\x63\157\165\x6e\164\162\171\40\143\x6f\144\x65\40\105\x67\56\x20\x2b\60\x30\x78\x78\x78\170\170\x78\170\x78\x78\x78"), "\x73\164\171\154\145" => "\167\x69\144\x74\x68\x3a\71\71\45\73\x6d\141\x72\147\151\x6e\55\142\157\164\x74\x6f\x6d\x3a\61\x25\x3b"));
        $form["\x6d\x69\x6e\151\157\x72\141\x6e\x67\x65\x5f\163\x61\155\154\137\x73\165\x70\160\x6f\x72\x74"]["\155\157\x5f\x73\141\155\154\x5f\x73\165\160\160\x6f\162\164\x5f\161\x75\145\x72\171"] = array("\43\164\171\160\x65" => "\x74\145\170\164\x61\162\x65\x61", "\x23\x74\x69\164\x6c\x65" => $this->t("\121\165\x65\162\x79"), "\x23\x72\x65\161\165\x69\162\x65\x64" => true, "\x23\141\164\164\162\151\x62\x75\164\x65\x73" => array("\160\154\141\143\145\x68\157\x6c\144\145\x72" => $this->t("\x44\145\163\143\x72\x69\142\x65\40\171\157\x75\162\40\161\x75\145\x72\x79\x20\150\x65\x72\x65\41"), "\x73\164\171\x6c\145" => "\167\x69\144\164\x68\72\71\x39\x25"), "\43\163\165\146\x66\151\170" => "\x3c\142\x72\x3e");
        $form["\x6d\151\x6e\151\x6f\162\141\156\x67\145\137\x73\141\x6d\x6c\x5f\x73\x75\x70\x70\157\x72\x74"]["\141\x63\164\x69\x6f\156\163"] = array("\43\x74\171\x70\145" => "\141\143\x74\x69\157\x6e\x73");
        $form["\155\x69\156\151\157\162\x61\156\x67\x65\x5f\x73\141\x6d\x6c\x5f\x73\165\160\x70\x6f\162\x74"]["\141\143\x74\x69\x6f\156\x73"]["\x73\165\x62\x6d\x69\x74"] = array("\43\164\x79\x70\145" => "\163\x75\x62\x6d\151\164", "\43\x62\165\164\164\x6f\x6e\x5f\164\x79\x70\x65" => "\160\162\x69\155\x61\162\171", "\x23\x76\x61\x6c\x75\145" => $this->t("\x53\165\142\155\x69\x74\x20\x71\165\145\x72\171"), "\x23\141\x74\x74\162\x69\x62\165\164\x65\163" => array("\x63\x6c\x61\163\x73" => array("\x75\163\x65\55\141\x6a\141\x78")), "\x23\141\152\x61\x78" => array("\143\141\x6c\154\x62\x61\143\x6b" => "\72\x3a\x73\x75\142\155\151\164\x51\x75\x65\x72\x79", "\160\x72\157\147\162\x65\163\163" => array("\x74\x79\160\x65" => "\x74\x68\x72\x6f\x62\142\x65\162", "\155\x65\163\163\141\147\145" => $this->t("\123\145\156\144\151\x6e\147\x20\121\165\145\162\x79\x2e\56\56"))));
        $form["\155\151\x6e\151\x6f\162\x61\x6e\x67\x65\137\x73\x61\x6d\154\137\x73\x75\160\160\x6f\162\164"]["\155\x61\x72\153\165\160\x5f\x73\165\160\x70\157\x72\x74\137\x6e\157\164\145"] = array("\x23\155\x61\x72\153\x75\160" => $this->t("\x3c\x64\x69\166\x3e\111\146\40\171\157\x75\40\x77\x61\156\164\x20\143\x75\x73\164\157\x6d\x20\x66\x65\141\x74\x75\162\145\163\40\151\156\40\164\150\x65\40\x6d\x6f\144\x75\x6c\145\x2c\12\40\40\40\x20\x20\x20\40\40\40\40\40\40\40\x20\x20\40\x20\x20\x20\40\x20\40\40\x20\x20\40\x6a\x75\x73\164\x20\x64\x72\x6f\160\40\141\x6e\x20\x65\155\141\151\x6c\40\x74\157\x20\74\141\x20\x68\162\145\146\75\x22\155\141\151\154\164\157\72\151\156\x66\157\x40\170\145\143\x75\162\x69\x66\x79\x2e\x63\x6f\155\x22\76\151\x6e\146\x6f\100\x78\145\x63\x75\x72\151\x66\171\56\143\157\x6d\x3c\57\141\76\40\x6f\x72\12\40\40\x20\x20\x20\x20\40\x20\x20\40\x20\x20\40\40\40\x20\40\40\x20\40\x20\40\x20\x20\40\40\74\141\x20\x68\162\x65\x66\75\42\155\x61\x69\154\164\x6f\72" . MiniorangeSAMLConstants::SUPPORT_EMAIL . "\42\x3e" . MiniorangeSAMLConstants::SUPPORT_EMAIL . "\74\x2f\x61\x3e\x3c\x2f\x64\151\166\76"));
        return $form;
    }
    public function submitForm(array &$form, FormStateInterface $form_state)
    {
    }
    public function submitQuery(array &$form, FormStateInterface $form_state)
    {
        $Yq = new AjaxResponse();
        if ($form_state->hasAnyErrors()) {
            goto Da;
        }
        $SH = $form_state->getValues();
        $vd = $SH["\x6d\157\137\x73\x61\x6d\154\x5f\163\x75\x70\x70\x6f\x72\164\137\145\x6d\x61\151\x6c\137\141\x64\144\162\x65\x73\x73"];
        $YV = $SH["\x6d\157\x5f\163\141\x6d\x6c\137\x73\165\x70\x70\157\162\x74\137\160\150\157\156\x65\137\x6e\x75\155\x62\145\x72"];
        $BJ = $SH["\155\x6f\137\x73\x61\x6d\154\x5f\163\x75\x70\x70\x6f\x72\164\x5f\x71\165\145\162\171"];
        $UC = "\x53\165\x70\160\x6f\162\x74";
        $h1 = Utilities::send_support_query($vd, $YV, $BJ, $UC);
        if ($h1) {
            goto o0;
        }
        $AM = array("\x23\164\x79\160\x65" => "\151\x74\x65\155", "\43\x6d\x61\162\153\x75\x70" => $this->t("\x45\x72\162\x6f\162\x20\163\165\142\155\151\164\164\x69\x6e\147\x20\164\x68\145\40\x73\x75\x70\x70\x6f\162\164\40\x71\165\x65\162\x79\56\40\x50\x6c\145\141\163\145\x20\x73\x65\x6e\x64\x20\165\163\40\x79\x6f\x75\x72\x20\161\x75\145\x72\171\x20\x61\x74\12\40\40\40\40\x20\40\x20\x20\x20\40\40\40\40\x20\x20\40\40\40\40\40\40\x20\x20\40\40\40\40\40\x20\x3c\x61\x20\x68\x72\145\x66\x3d\42\155\x61\x69\x6c\164\x6f\72\144\162\x75\x70\141\154\163\x75\x70\x70\157\x72\164\x40\170\x65\143\x75\x72\151\x66\x79\x2e\x63\x6f\155\42\x3e\xa\x20\x20\40\40\x20\x20\x20\40\40\40\x20\40\40\40\40\40\40\40\x20\40\40\x20\40\40\40\40\40\x20\40\x64\162\x75\160\141\x6c\x73\x75\160\160\157\162\x74\x40\170\x65\143\165\x72\x69\146\171\56\x63\157\155\x3c\57\x61\x3e\56"));
        $dd = new OpenModalDialogCommand("\x45\162\162\x6f\162\x21", $AM, ["\167\151\144\x74\150" => "\65\x30\x25"]);
        goto MT;
        o0:
        $nl = array("\43\164\x79\x70\x65" => "\x69\164\x65\155", "\43\x6d\x61\x72\153\165\160" => $this->t("\124\150\x61\x6e\x6b\x73\40\x66\x6f\x72\x20\147\145\x74\164\x69\156\147\40\x69\156\40\x74\x6f\165\x63\150\41\x20\127\145\40\x77\x69\x6c\154\40\x67\145\x74\x20\x62\x61\143\x6b\x20\x74\x6f\x20\171\157\x75\40\163\x68\x6f\x72\x74\x6c\171\x2e"));
        $dd = new OpenModalDialogCommand("\124\150\x61\156\153\x20\171\x6f\x75\41", $nl, ["\167\x69\x64\x74\x68" => "\x35\60\45"]);
        MT:
        $Yq->addCommand($dd);
        goto cj;
        Da:
        $Yq->addCommand(new ReplaceCommand("\43\155\157\144\x61\x6c\137\x73\165\160\160\x6f\162\164\137\x66\157\162\155", $form));
        cj:
        return $Yq;
    }
}
