$path = $HOME . '/.composer/vendor/legovaer/phpcov-runner/lib";
set_include_path(get_include_path() . PATH_SEPARATOR . $path);
require "autocoverage.php";
