<?php


namespace Drupal\miniorange_saml\Form;

use Drupal\Core\Form\FormBase;
use Drupal\Core\Ajax\HtmlCommand;
use Drupal\Core\Ajax\AjaxResponse;
use Drupal\Core\Ajax\ReplaceCommand;
use Drupal\Core\Ajax\RedirectCommand;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Ajax\OpenModalDialogCommand;
use Drupal\miniorange_saml\AESEncryption;
use Drupal\miniorange_saml\MiniorangeSAMLCustomer;
use Drupal\miniorange_saml\Utilities;
class MiniorangeSAMLRemoveLicense extends FormBase
{
    public function getFormId()
    {
        return "\155\151\x6e\x69\x6f\x72\x61\156\147\x65\137\x73\141\x6d\x6c\x5f\162\x65\155\x6f\x76\x65\137\x6c\x69\x63\145\x6e\163\145";
    }
    public function buildForm(array $form, FormStateInterface $form_state, $GK = NULL)
    {
        $form["\x23\160\162\145\146\x69\170"] = "\x3c\144\151\166\40\151\144\75\x22\155\157\x64\x61\154\137\x65\170\x61\155\x70\154\145\x5f\146\x6f\162\155\x22\x3e";
        $form["\43\x73\165\x66\x66\x69\x78"] = "\74\57\x64\151\166\76";
        $form["\x73\x74\141\164\x75\163\x5f\x6d\145\x73\x73\141\147\145\x73"] = ["\x23\164\x79\x70\145" => "\163\164\141\x74\165\x73\x5f\x6d\145\x73\163\x61\x67\145\163", "\43\x77\x65\x69\x67\150\164" => -10];
        $form["\155\151\x6e\151\x6f\162\141\156\147\145\x5f\163\141\155\x6c\x5f\143\157\x6e\x74\x65\156\x74"] = array("\x23\155\141\x72\153\x75\x70" => "\x41\x72\x65\x20\x79\x6f\x75\x20\x73\x75\162\145\40\171\x6f\x75\x20\x77\141\x6e\x74\x20\x74\157\40\x72\x65\x6d\x6f\166\x65\x20\164\x68\x65\x20\114\151\x63\x65\x6e\163\145\x20\153\145\x79\x3f\40\x54\x68\x65\40\x63\x6f\x6e\146\x69\x67\x75\162\141\x74\151\x6f\156\163\x20\163\x61\x76\x65\x64\40\x77\x69\154\154\40\x6e\157\164\40\x62\x65\x20\154\x6f\x73\164\x2e");
        $form["\x61\143\x74\151\157\x6e\x73"] = array("\x23\x74\171\x70\145" => "\141\x63\164\x69\x6f\x6e\163");
        $form["\x61\x63\x74\x69\x6f\156\x73"]["\x73\x65\156\144"] = ["\43\x74\x79\160\x65" => "\163\165\x62\x6d\151\164", "\x23\x76\x61\x6c\x75\145" => $this->t("\103\157\156\146\151\162\x6d"), "\x23\141\x74\x74\162\x69\x62\165\x74\145\x73" => ["\x63\154\141\x73\163" => ["\x75\x73\145\55\x61\x6a\141\x78"]], "\43\x61\152\141\x78" => ["\x63\141\154\x6c\142\141\143\153" => [$this, "\163\x75\x62\x6d\151\x74\115\157\144\x61\x6c\106\x6f\162\x6d\x41\152\141\x78"], "\145\x76\145\156\164" => "\143\154\151\x63\x6b"]];
        $form["\43\x61\x74\164\x61\x63\150\145\x64"]["\x6c\x69\142\x72\141\162\171"][] = "\x63\x6f\162\x65\57\x64\x72\165\160\x61\154\56\x64\151\x61\x6c\x6f\147\56\x61\x6a\141\170";
        return $form;
    }
    public function submitModalFormAjax(array $form, FormStateInterface $form_state)
    {
        $f5 = \Drupal::config("\155\151\x6e\151\x6f\162\141\x6e\x67\x65\137\x73\141\x6d\x6c\x2e\163\x65\164\x74\151\x6e\147\x73");
        $yQ = $f5->get("\x6d\151\x6e\x69\x6f\162\x61\156\147\x65\x5f\x73\x61\155\x6c\x5f\143\165\163\164\x6f\x6d\x65\162\x5f\141\x64\155\151\x6e\x5f\164\x6f\x6b\x65\x6e");
        $sV = \Drupal::configFactory()->getEditable("\155\x69\x6e\x69\x6f\162\141\156\x67\x65\x5f\163\x61\x6d\154\x2e\x73\x65\164\x74\x69\156\x67\163");
        $wU = AESEncryption::decrypt_data($sV->get("\x6d\x69\156\157\162\x61\156\x67\x65\137\x73\x61\x6d\x6c\x5f\x63\165\x73\164\x6f\155\x65\x72\137\x61\144\155\x69\156\x5f\x66\x72\141\165\x64\x5f\x63\150\x65\143\x6b"), $yQ);
        $dl = Utilities::moStoreDomainInDatabase($yQ, 1);
        $Yq = new AjaxResponse();
        if ($form_state->hasAnyErrors()) {
            goto YH;
        }
        if (!($f5->get("\x6d\151\x6e\x69\157\x72\141\156\147\x65\x5f\x73\x61\x6d\154\x5f\x6c\x69\x63\145\x6e\x73\145\x5f\x6b\145\171") != NULL)) {
            goto Zy;
        }
        $PV = new MiniorangeSAMLCustomer($f5->get("\155\x69\156\151\x6f\x72\141\156\x67\x65\x5f\163\141\x6d\x6c\137\143\165\x73\x74\157\x6d\145\x72\x5f\141\x64\x6d\151\x6e\x5f\145\155\x61\x69\154"), $f5->get("\x6d\151\156\x69\157\162\x61\x6e\147\145\137\x73\141\155\154\x5f\x63\165\163\x74\157\155\x65\162\x5f\x61\x64\155\x69\156\x5f\x70\150\157\156\x65"), NULL, NULL);
        if (!($dl == $wU)) {
            goto xw;
        }
        $w1 = $PV->updateStatus() !== NULL ? json_decode($PV->updateStatus()) : '';
        if (!(!is_object($w1) || !isset($w1->status) || empty($w1->status))) {
            goto pX;
        }
        \Drupal::messenger()->addMessage(t("\x45\162\162\157\162\x3a\x53\157\155\145\164\x68\x69\156\x67\40\167\145\x6e\x74\x20\x77\162\157\x6e\x67\40\167\150\x69\x6c\145\40\x70\x72\157\x63\x65\163\163\x69\156\x67\x20\171\x6f\165\162\40\162\x65\161\165\x65\x73\x74\x2e\x20\x52\x65\x66\x65\162\x65\156\143\145\x20\x4e\x6f\56\72\x44\x38\x53\x53\105\174\60\x30\x30\71"), "\x65\162\162\x6f\x72");
        return;
        pX:
        xw:
        $sV->clear("\155\151\x6e\151\157\x72\x61\x6e\x67\x65\x5f\163\141\155\x6c\x5f\x6c\151\143\145\x6e\163\x65\x5f\x6b\x65\171")->save();
        $sV->clear("\x6d\x69\x6e\151\x6f\x72\141\156\147\x65\137\163\141\155\x6c\x5f\x63\165\x73\x74\157\155\145\x72\137\141\x64\x6d\x69\x6e\137\x65\x6d\x61\x69\154")->save();
        $sV->clear("\x6d\151\x6e\x69\157\162\x61\x6e\147\x65\137\163\x61\155\x6c\137\x63\165\163\x74\157\155\145\162\x5f\141\144\155\151\x6e\137\160\x68\157\x6e\x65")->save();
        $sV->clear("\x6d\x69\x6e\x69\x6f\x72\x61\x6e\x67\145\x5f\163\x61\155\x6c\137\x63\165\163\x74\x6f\155\x65\162\137\141\160\151\137\x6b\145\171")->save();
        $sV->clear("\155\x69\x6e\151\157\x72\141\x6e\x67\145\x5f\x73\x61\155\154\137\143\165\163\x74\157\155\x65\x72\137\x61\x64\x6d\151\156\x5f\x74\157\x6b\x65\x6e")->save();
        $sV->set("\x6d\x69\156\x69\x6f\x72\141\156\147\x65\x5f\163\x61\x6d\x6c\137\x73\x74\x61\x74\165\163", "\x43\125\x53\124\117\x4d\105\x52\x5f\x53\x45\124\x55\120")->save();
        if (empty($sV->get("\155\x69\x6e\x69\x6f\162\x61\156\147\x65\x5f\x73\141\155\154\x5f\x6c\151\143\x65\x6e\163\145\137\x6b\x65\x79"))) {
            goto co;
        }
        \Drupal::messenger()->addMessage(t("\105\162\x72\x6f\162\x3a\123\x6f\155\145\164\x68\151\156\x67\40\167\145\x6e\164\x20\x77\162\x6f\156\147\x20\167\x68\151\x6c\x65\40\x70\x72\157\143\145\x73\163\151\x6e\147\x20\x79\x6f\x75\x72\40\x72\x65\x71\165\145\163\164\x2e\40\122\145\146\x65\x72\x65\156\x63\x65\x20\116\157\x2e\72\x44\x38\123\x53\x45\174\60\60\61\60"), "\x65\x72\x72\157\162");
        goto jV;
        co:
        \Drupal::messenger()->addMessage(t("\131\157\165\x72\40\x41\143\x63\157\x75\x6e\x74\40\110\x61\x73\40\102\145\145\156\x20\x52\145\155\x6f\166\145\x64\40\x53\x75\143\143\x65\x73\x73\146\165\154\154\x79\x21"), "\x73\164\x61\x74\x75\163");
        jV:
        Zy:
        $Yq->addCommand(new RedirectCommand(\Drupal\Core\Url::fromRoute("\155\151\x6e\151\157\162\x61\156\x67\x65\137\163\x61\x6d\x6c\x2e\143\165\163\x74\x6f\x6d\145\162\x5f\x73\145\x74\x75\x70")->toString()));
        goto H2;
        YH:
        $Yq->addCommand(new ReplaceCommand("\43\155\157\144\x61\x6c\x5f\x65\170\141\x6d\160\x6c\145\137\x66\157\162\155", $form));
        H2:
        return $Yq;
    }
    public function validateForm(array &$form, FormStateInterface $form_state)
    {
    }
    public function submitForm(array &$form, FormStateInterface $form_state)
    {
    }
    protected function getEditableConfigNames()
    {
        return ["\x63\157\x6e\146\x69\x67\x2e\x6d\x69\x6e\x69\157\162\141\x6e\147\x65\x5f\x73\141\x6d\154\137\162\x65\x6d\x6f\166\x65\137\x6c\x69\143\145\156\163\x65"];
    }
}
