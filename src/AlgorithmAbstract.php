<?php

namespace Hacking;

abstract class AlgorithmAbstract
{
    protected $html;

    public function __construct($html)
    {
        $this->html = $html;
    }
}