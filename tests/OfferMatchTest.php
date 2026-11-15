<?php

declare(strict_types=1);

namespace Quebracho\X402\Tests;

use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Quebracho\X402\EvmExact;
use Quebracho\X402\FileClaims;
use Quebracho\X402\Networks;
use Quebracho\X402\PaymentHeaders;
use Quebracho\X402\Settlement;
use Quebracho\X402\Signer;
use Quebracho\X402\X402McpMiddleware;
use Quebracho\X402\X402Middleware;

/**
 * A seller may offer two tokens on one network. The buyer says which offer it took (`accepted`); the seller
 * finds it among its own by scheme, network and asset. By scheme and network alone it always took the first,
 * and whoever paid with the second token was refused.
 */
final class OfferMatchTest extends TestCase
{
    use TempClaims;

    private const KEY = '0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318';
    private const OTHER_TOKEN = '0x00000000000000000000000000000000000E0BC0';

    private int $runs = 0;

    /** @return list<array<string, mixed>> USDC first, then another EIP-3009 token on the same network, at another price */
    private static function accepts(): array
    {
        $usdc = Networks::requirements('eip155:84532', '0.01', '0x000000000000000000000000000000000000dEaD');
        $other = ['asset' => self::OTHER_TOKEN, 'amount' => '9000', 'extra' => ['name' => 'Other Coin', 'version' => '1']] + $usdc;

        return [$usdc, $other];
    }

    private static function pay(array $req): array
    {
        return (new EvmExact(new Signer(self::KEY)))->pay(['x402Version' => 2, 'resource' => ['url' => 'https://example.test/paid'], 'accepts' => self::accepts()], $req);
    }

    private function http(): X402Middleware
    {
        $f = new Psr17Factory();

        return new X402Middleware([new EvmExact()], static fn () => self::accepts(), (new FileClaims($this->claimsDir()))->__invoke(...), $f, $f, Settlement::mock());
    }

    public function testTheHttpSellerTakesAPaymentOfItsSecondOffer(): void
    {
        $response = $this->http()->process($this->request(self::pay(self::accepts()[1])), $this->handler(new Response(200, [], 'paid content')));

        self::assertSame(200, $response->getStatusCode(), (string) $response->getBody());
        self::assertSame(1, $this->runs);
        self::assertTrue(PaymentHeaders::decode($response->getHeaderLine(PaymentHeaders::RESPONSE))['success']);
    }

    public function testTheFirstOfferIsStillTaken(): void
    {
        self::assertSame(200, $this->http()->process($this->request(self::pay(self::accepts()[0])), $this->handler(new Response(200, [], 'paid content')))->getStatusCode());
    }

    public function testTheAssetMatchesInAnyCaseOnEvm(): void
    {
        $payment = self::pay(self::accepts()[1]);
        $payment['accepted']['asset'] = strtolower($payment['accepted']['asset']);

        self::assertSame(200, $this->http()->process($this->request($payment), $this->handler(new Response(200, [], 'paid content')))->getStatusCode());
    }

    /**
     * The offer is still the seller's own, never the buyer's copy: a payment that names a token the seller does
     * not offer is checked against the seller's first offer on that network, and refused.
     */
    public function testATokenTheSellerDoesNotOfferBuysNothing(): void
    {
        $mine = ['asset' => '0x0000000000000000000000000000000000000BAD', 'amount' => '1', 'extra' => ['name' => 'Mine', 'version' => '1']] + self::accepts()[0];
        $response = $this->http()->process($this->request(self::pay($mine)), $this->handler(new Response(200, [], 'paid content')));

        self::assertSame(402, $response->getStatusCode());
        self::assertSame(0, $this->runs);
    }

    /** The second token's price is its own: paying it the first offer's way (or the other way round) is refused. */
    public function testAnOfferIsPaidAtItsOwnPrice(): void
    {
        $payment = self::pay(['amount' => '1'] + self::accepts()[1]);
        $response = $this->http()->process($this->request($payment), $this->handler(new Response(200, [], 'paid content')));

        self::assertSame(402, $response->getStatusCode());
        self::assertSame(0, $this->runs);
    }

    public function testTheMcpSellerTakesAPaymentOfItsSecondOffer(): void
    {
        $f = new Psr17Factory();
        $seller = new X402McpMiddleware([new EvmExact()], static fn () => self::accepts(), (new FileClaims($this->claimsDir()))->__invoke(...), $f, $f, Settlement::mock());
        $call = ['jsonrpc' => '2.0', 'id' => 2, 'method' => 'tools/call', 'params' => ['name' => 'wisdom', 'arguments' => [], '_meta' => [X402McpMiddleware::PAYMENT => self::pay(self::accepts()[1])]]];
        $response = $seller->process(new ServerRequest('POST', 'https://example.test/mcp', [], json_encode($call)), $this->handler(new Response(200, ['Content-Type' => 'application/json'], '{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"paid content"}]}}')));

        $result = json_decode((string) $response->getBody(), true)['result'];
        self::assertArrayNotHasKey('isError', $result, json_encode($result));
        self::assertTrue($result['_meta'][X402McpMiddleware::PAYMENT_RESPONSE]['success']);
        self::assertSame(1, $this->runs);
    }

    private function request(array $payment): ServerRequest
    {
        return new ServerRequest('POST', 'https://example.test/paid', [PaymentHeaders::SIGNATURE => PaymentHeaders::encode($payment)]);
    }

    private function handler(ResponseInterface $response): RequestHandlerInterface
    {
        return new class($this->runs, $response) implements RequestHandlerInterface {
            public function __construct(private int &$runs, private ResponseInterface $response)
            {
            }

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                ++$this->runs;

                return $this->response;
            }
        };
    }
}
