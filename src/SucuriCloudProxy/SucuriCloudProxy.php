<?php

namespace Hacking\SucuriCloudProxy;

use Hacking\AlgorithmAbstract;

class SucuriCloudProxy extends AlgorithmAbstract
{
    private $resultBase64;
    private $cookieName;
    private $cookieCode;

    public function __construct($html)
    {
        parent::__construct($html);
    }

    /**
     * @throws \Exception
     */
    public function getCookie()
    {
        preg_match('/sucuri_cloudproxy_js=["\']{2},S=(\'|")([^\']+)\1/sui', $this->html, $m);
        if (empty($m)) {
            throw new \Exception('Не найден base64');
        }
        $this->resultBase64 = base64_decode($m[2]);
        $this->getName()->getValue();
        return [
            'name' => $this->cookieName,
            'value' => $this->cookieCode,
        ];
    }

    /**
     * @return $this
     * @throws \Exception
     */
    private function getName()
    {
        preg_match('/document.cookie=([^;]+)\s*\+\s*("|\')=\2/sui', $this->resultBase64, $m);
        if (empty($m)) {
            throw new \Exception('Не найдена переменная с именем cookie');
        }
        $arName = array_map('trim', explode('+', $m[1]));
        $this->cookieName = '';
        foreach ($arName as $code) {
            $this->cookieName .= $this->getResult($code);
        }
        return $this;
    }

    /**
     * @throws \Exception
     */
    private function getValue()
    {
        preg_match('/^[a-z]=([^;]+)/sui', $this->resultBase64, $m);
        if (empty($m)) {
            throw new \Exception('Не найдена переменная с кодом cookie');
        }
        $arCode = array_map('trim', explode('+', $m[1]));
        $this->cookieCode = '';
        foreach ($arCode as $code) {
            $this->cookieCode .= $this->getResult($code);
        }
        return $this;
    }

    private function getResult($code)
    {
        if (preg_match('/^("|\')[^\1]\1$/sui', $code)) {
            return preg_replace('/["\']/', '', $code);
        } elseif (preg_match('/(\'|")([^\1]+)\1\.charAt\((\d+)\)/sui', $code, $m)) {
            return $m[2][(int)$m[3]];
        } elseif (preg_match('/(\'|")([^\1]+)\1\.substr\((\d+),\s*(\d+)\)/sui', $code, $m)) {
            return substr($m[2], $m[3], $m[4]);
        } elseif (preg_match('/String\.fromCharCode\(0x([0-9a-f]+)\)/sui', $code, $m)) {
            return chr(hexdec($m[1]));
        } elseif (preg_match('/String\.fromCharCode\(([0-9]+)\)/sui', $code, $m)) {
            return chr($m[1]);
        } elseif (preg_match('/(\'|")([^\1]+)\1\.slice\((\d+),\s*([0-9\-\+]+)\)/sui', $code, $m)) {
            $begin = (int)$m[3];
            $end = (int)$m[4];
            if ($end < 0) {
                $end = strlen($m[2]) - $end - $begin;
            } elseif ($end > 0) {
                $end -= $begin;
            }
            return substr($m[2], $begin, $end);
        }
        return '';
    }
}