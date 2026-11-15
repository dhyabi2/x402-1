<?php

declare(strict_types=1);

namespace Quebracho\X402\Tests;

use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Quebracho\X402\AuthorizationState;
use Quebracho\X402\ChainFacilitator;
use Quebracho\X402\CircleFacilitator;
use Quebracho\X402\EvmExact;
use Quebracho\X402\FileClaims;
use Quebracho\X402\FileLedger;
use Quebracho\X402\InvalidPaymentException;
use Quebracho\X402\Networks;
use Quebracho\X402\PaymentHeaders;
use Quebracho\X402\Settlement;
use Quebracho\X402\Signer;
use Quebracho\X402\X402McpMiddleware;
use Quebracho\X402\X402Middleware;

/**
 * What a buyer sends is read in one spelling only. A value with something after it (a newline, which a PCRE
 * `$` lets through) used to reach the EIP-712 encoder and throw there (a 500 anybody could cause), or pass as
 * a second spelling of the same payment.
 */
final class StrictInputTest extends TestCase
{
    use TempClaims;

    private const KEY = '0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318';

    private int $runs = 0;

    private static function req(): array
    {
        return Networks::requirements('eip155:84532', '0.01', '0x000000000000000000000000000000000000dEaD');
    }

    private static function payment(): array
    {
        return (new EvmExact(new Signer(self::KEY)))->pay(['x402Version' => 2, 'resource' => ['url' => 'https://example.test/mcp'], 'accepts' => [self::req()]], self::req());
    }

    /** @return iterable<string, array{string, string}> the field, and what is added after its value */
    public static function trailing(): iterable
    {
        foreach (['from', 'to', 'value', 'validAfter', 'validBefore', 'nonce', 'signature'] as $field) {
            foreach (['a newline' => "\n", 'a space' => ' ', 'a NUL' => "\0", 'CRLF' => "\r\n"] as $name => $tail) {
                yield "$field with $name" => [$field, $tail];
            }
        }
    }

    private static function with(string $field, string $tail): array
    {
        $payment = self::payment();
        if ('signature' === $field) {
            $payment['payload']['signature'] .= $tail;
        } else {
            $payment['payload']['authorization'][$field] .= $tail;
        }

        return $payment;
    }

    #[DataProvider('trailing')]
    public function testTheSchemeRefusesItAndDoesNotThrow(string $field, string $tail): void
    {
        self::assertSame('invalid_payload', (new EvmExact())->verify(self::with($field, $tail), self::req()));
    }

    #[DataProvider('trailing')]
    public function testTheHttpSellerAnswers402AndRunsNothing(string $field, string $tail): void
    {
        $f = new Psr17Factory();
        $req = self::req();
        // With a ledger: it reads the payment first (Sale::stored), where the encoder used to throw.
        $seller = new X402Middleware([new EvmExact()], static fn () => [$req], static fn () => true, $f, $f, Settlement::mock(), ledger: new FileLedger($this->claimsDir()));
        $request = new ServerRequest('POST', 'https://example.test/paid', [PaymentHeaders::SIGNATURE => PaymentHeaders::encode(self::with($field, $tail))]);
        $response = $seller->process($request, $this->handler(new Response(200, [], 'paid content')));

        self::assertSame(402, $response->getStatusCode());
        self::assertSame('invalid_payload', json_decode((string) $response->getBody(), true)['error']);
        self::assertSame(0, $this->runs);
    }

    #[DataProvider('trailing')]
    public function testTheMcpSellerAnswersPaymentRequiredAndRunsNothing(string $field, string $tail): void
    {
        $f = new Psr17Factory();
        $req = self::req();
        $seller = new X402McpMiddleware([new EvmExact()], static fn () => [$req], (new FileClaims($this->claimsDir()))->__invoke(...), $f, $f, Settlement::mock(), ledger: new FileLedger($this->claimsDir().'/ledger'));
        $call = ['jsonrpc' => '2.0', 'id' => 2, 'method' => 'tools/call', 'params' => ['name' => 'wisdom', 'arguments' => [], '_meta' => [X402McpMiddleware::PAYMENT => self::with($field, $tail)]]];
        $response = $seller->process(new ServerRequest('POST', 'https://example.test/mcp', [], json_encode($call)), $this->handler(new Response(200, ['Content-Type' => 'application/json'], '{"jsonrpc":"2.0","id":2,"result":{"content":[]}}')));

        $result = json_decode((string) $response->getBody(), true)['result'];
        self::assertTrue($result['isError']);
        self::assertSame('invalid_payload', $result['structuredContent']['error']);
        self::assertSame(0, $this->runs);
    }

    /**
     * A seller's own offer the encoder cannot read (a token that is no address) is a refusal that names the
     * offer, never an exception: it must not turn every payment into a 500.
     */
    public function testAnOfferTheEncoderCannotReadIsARefusal(): void
    {
        foreach (['asset', 'payTo'] as $field) {
            $req = [$field => 'not-an-address'] + self::req();
            $payment = self::payment();
            $payment['accepted'][$field] = 'not-an-address';

            self::assertSame('invalid_payment_requirements', (new EvmExact())->verify($payment, $req), $field);
        }
    }

    #[DataProvider('trailing')]
    public function testTheChainFacilitatorBuildsNoCalldataFromIt(string $field, string $tail): void
    {
        $this->expectException(InvalidPaymentException::class);
        ChainFacilitator::calldata(self::with($field, $tail));
    }

    public function testASignatureWithATailRecoversNobody(): void
    {
        $payment = self::payment();
        $digest = \Quebracho\X402\Authorization::digest(self::req(), $payment['payload']['authorization']);
        self::assertNotNull(Signer::recover($digest, $payment['payload']['signature']));
        self::assertNull(Signer::recover($digest, $payment['payload']['signature']."\n"));
    }

    public function testAPrivateKeyWithATailIsNoKey(): void
    {
        // Read from a file with its final newline: refused at boot, not signed with in some other reading.
        $this->expectException(\InvalidArgumentException::class);
        new Signer(self::KEY."\n");
    }

    public function testAPaymentIdWithATailIsNotAskedAbout(): void
    {
        $f = new Psr17Factory();
        $circle = new CircleFacilitator(new class implements \Psr\Http\Client\ClientInterface {
            public function sendRequest(\Psr\Http\Message\RequestInterface $request): ResponseInterface
            {
                throw new \LogicException('Nothing may be sent for a bad paymentId: '.$request->getUri());
            }
        }, $f, $f, 'key');
        $this->expectException(\InvalidArgumentException::class);
        $circle->status("abc\n", 'eip155:5042002');
    }

    public function testAuthorizationStateRefusesATail(): void
    {
        $f = new Psr17Factory();
        $state = new AuthorizationState(new class implements \Psr\Http\Client\ClientInterface {
            public function sendRequest(\Psr\Http\Message\RequestInterface $request): ResponseInterface
            {
                throw new \LogicException('Nothing may be asked about a bad nonce.');
            }
        }, $f, $f);
        $this->expectException(\InvalidArgumentException::class);
        $state('eip155:84532', '0x000000000000000000000000000000000000dEaD', '0x'.str_repeat('00', 32)."\n");
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
