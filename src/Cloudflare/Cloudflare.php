<?php

namespace AppBundle\Service\Hacking;

class Cloudflare
{
    private $html;
    private $website;
    private $answer;
    private $params;

    public function __construct($website, $html)
    {
        $this->website = preg_replace('/\/$/sui', '', $website);
        $this->html = $html;
    }

    /**
     * @return array
     * @throws \Exception
     */
    public function getParams()
    {
        $this->calculationAnswer();
        $this->params = [];
        preg_match_all('/<input\s.+?name=(\'|")(.+?)\1\s+value=("|\')(.+?)\3/sui', $this->html, $matches);
        if (empty($matches)) {
            throw new \Exception('В форме не найдены имена дополнительных переменных для отправки результата.');
        }
        foreach ($matches[2] as $key => $name) {
            $this->params[$name] = $matches[4][$key];
        }
        preg_match('/<input\s[^>]+name=(\'|")([^$1]+answer)\1/sui', $this->html, $answer);
        if (empty($answer)) {
            throw new \Exception('Не найдено имя переменной для отправки результата.');
        }
        $this->params[$answer[2]] = $this->answer;
        return $this->params;
    }

    public function getUsleep()
    {
        if (empty($this->params['pass'])) {
            return 0;
        }
        preg_match('/\d+\.(\d+)/sui', $this->params['pass'], $m);
        $n = 4 + (round($m[1] / 100) / 10);
        return $n * 1e6;
    }

    /**
     * @return string
     * @throws \Exception
     */
    public function getPath()
    {
        preg_match('/<form\s[^>]+\saction=(\'|")(.+?)\1/sui', $this->html, $path);
        if (empty($path)) {
            throw new \Exception('Не найден путь для отправки результата');
        }
        return $this->website . $path[2];
    }

    /**
     * @return $this
     * @throws \Exception
     */
    private function calculationAnswer()
    {
        preg_match('/([a-z]+)={"([a-z]+)":\+(.+?)}/sui', $this->html, $match);
        if (empty($match) || count($match) != 4) {
            throw new \Exception('Не найдена переменная для расчетов.');
        }
        $variable = $match[1] . '\.' . $match[2];
        $this->answer = $this->calculationExpression($match[3]);
        preg_match_all('/' . $variable . '([+\/\-*])=\+(.+?);/sui', $this->html, $expressions);
        if (empty($expressions)) {
            throw new \Exception('Не найдены дополнительные выражения для расчета.');
        }
        foreach ($expressions[1] as $key => $sign) {
            switch ($sign) {
                case '+':
                    $this->answer += $this->calculationExpression($expressions[2][$key]);
                    break;
                case'-':
                    $this->answer -= $this->calculationExpression($expressions[2][$key]);
                    break;
                case'*':
                    $this->answer *= $this->calculationExpression($expressions[2][$key]);
                    break;
                case'/':
                    $this->answer /= $this->calculationExpression($expressions[2][$key]);
                    break;
            }
        }
        $host = parse_url($this->website, PHP_URL_HOST);
        $this->answer = round($this->answer + mb_strlen($host, 'utf-8'), 10);
        $this->answer = number_format($this->answer, 10, '.', '');
        return $this;
    }

    /**
     * @param $str
     * @return float|int
     * @throws \Exception
     */
    private function calculationExpression($str)
    {
        preg_match_all('/\(([^\(\)]+?)\)/sui', $str, $expressions);
        if (empty($expressions)) {
            throw new \Exception('Невозможно разбить дополнительное выражение для дальнейшего расчета. '
                . $str);
        }
        foreach ($expressions[1] as $expression) {
            $result = $this->getSum($expression);
            $search = '(' . $expression . ')';
            $pos = strpos($str, $search);
            $str = substr_replace($str, $result, $pos, strlen($search));
        }
        preg_match('/\((.+?)\)\/\+\((.+?)\)/sui', $str, $match);
        if (empty($match)) {
            throw new \Exception('Не найдено предполагаемое деление выражений.');
        }
        return preg_replace('/\+/', '', $match[1])
            / preg_replace('/\+/', '', $match[2]);
    }

    /**
     * @param $expression
     * @return int
     * @throws \Exception
     */
    private function getSum($expression)
    {
        $sum = 0;
        preg_match_all('/(.+?\])/sui', $expression, $matches);
        foreach ($matches[1] as $item) {
            switch ($item) {
                case'!+[]':
                case'+!![]':
                    $sum++;
                    break;
                case'+[]':
                    break;
                default:
                    throw new \Exception('Неизвестная переменная в расчете. '
                        . json_encode($matches[1], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT));
                    break;
            }
        }
        return $sum;
    }
}