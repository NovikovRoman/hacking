Для `cloudflare` необходимы заголовки:
- `Cache-Control: no-cache`
- `Pragma: no-cache`
- `User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:63.0) Gecko/20100101 Firefox/63.0`
- `TE: Trailers`
- `Accept: text/html,application/xhtml+xm…plication/xml;q=0.9,*/*;q=0.8`
- `Accept-Encoding: gzip, deflate, br`
- `Accept-Language: ru,en-US;q=0.7,en;q=0.3`

`Cloudflare` может запросить несколько `challenge`. Пример:
```php
$url = '…';
$userAgent = 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:63.0) Gecko/20100101 Firefox/63.0';
try {
    $params = [
        'timeout' => 10,
        'connect_timeout' => 30,
        'allow_redirects' => false,
        'cookies' => new GuzzleHttp\Cookie\CookieJar(),
        'headers' => [
            'base_uri' => 'https://site.com', // подставить нужное
            'Origin' => 'https://site.com', // подставить нужное
            'Host' => 'site.com', // подставить нужное
            'Cache-Control' => 'no-cache',
            'Pragma' => 'no-cache',
            'User-Agent' => $userAgent,
            'TE' => 'Trailers',
            'Accept' => 'text/html,application/xhtml+xm…plication/xml;q=0.9,*/*;q=0.8',
            'Accept-Encoding' => 'gzip, deflate, br',
            'Accept-Language' => 'ru,en-US;q=0.7,en;q=0.3',
        ],
        'verify' => false,
    ];
    $httpClient = new GuzzleHttp\Client(['headers' => ['User-Agent' => $userAgent]]);
    $response = $httpClient->request('GET', $url, $params);
    $html = $response->getBody()->getContents();
} catch (RequestException $e) {
    $html = $e->getResponse()->getBody()->getContents();
    while ($e && $e->getResponse()->getStatusCode() == 503
        && preg_match('/DDoS protection by Cloudflare/sui', $html)) {
        $c = new GuzzleHttp\Cookie\CookieJar();
        foreach ($e->getResponse()->getHeader('Set-Cookie') as $cookie) {
            $c->setCookie(SetCookie::fromString($cookie));
        }
        $this->params['allow_redirects'] = [
            'max' => 5,
            'strict' => false,
            'referer' => false,
            'protocols' => ['https'],
            'track_redirects' => false
        ];
        $params['verify'] = true;
        $params['cookies'] = $c;
        $parseUrl = parse_url($url);
        $website = $parseUrl['scheme'] . '://' . $parseUrl['host'];
        $params['headers']['Referer'] = $url;
        $params['headers']['Host'] = $parseUrl['host'];
        $cf = new Cloudflare($website, $html);
        $params['query'] = $cf->getParams();
        usleep($cf->getUsleep());
        $e = null;
        try {
            $response = $httpClient->request('GET', $cf->getPath(), $this->params);
            $html = $response->getBody()->getContents();
        } catch (RequestException $e) {
            $html = $e->getResponse()->getBody()->getContents();
        }
    }
    if ($e) {
        throw new \Exception('Страница недоступна ' . $e->getMessage());
    }
} catch (\Exception $e) {
    throw new \Exception('Страница недоступна ' . $e->getMessage());
}
// обработка $html
// можно получать другие страницы с настроенным $params
``` 