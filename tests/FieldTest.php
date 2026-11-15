<?php

declare(strict_types=1);

namespace Quebracho\X402\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Quebracho\X402\Field;

final class FieldTest extends TestCase
{
    private const ADDRESS = '0x000000000000000000000000000000000000dEaD';

    /** @return iterable<string, array{string, string}> a rule and one value in its only spelling */
    public static function good(): iterable
    {
        yield 'address' => [Field::ADDRESS, self::ADDRESS];
        yield 'bytes32' => [Field::BYTES32, '0x'.str_repeat('aB', 32)];
        yield 'signature' => [Field::SIGNATURE, '0x'.str_repeat('1c', 65)];
        yield 'private key' => [Field::PRIVATE_KEY, '0x'.str_repeat('11', 32)];
        yield 'uint256 zero' => [Field::UINT256, '0'];
        yield 'uint256' => [Field::UINT256, str_repeat('9', 78)];
        yield 'amount' => [Field::AMOUNT, '10000'];
        yield 'timestamp zero' => [Field::TIMESTAMP, '0'];
        yield 'timestamp' => [Field::TIMESTAMP, '1800000000'];
        yield 'payment id' => [Field::PAYMENT_ID, 'a1b2-c3_d4'];
        yield 'evm network' => [Field::EVM_NETWORK, 'eip155:84532'];
        yield 'base58' => [Field::BASE58, 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v'];
        yield 'hash' => [Field::HASH, str_repeat('0f', 32)];
        yield 'job id' => [Field::JOB_ID, str_repeat('0f', 16)];
    }

    #[DataProvider('good')]
    public function testTakesTheOneSpelling(string $rule, string $value): void
    {
        self::assertTrue(Field::is($rule, $value));
    }

    /**
     * A PCRE `$` also matches before a final newline: "0xabc…\n" passed, and then broke the encoder or went
     * on to the facilitator in a second spelling.
     */
    #[DataProvider('good')]
    public function testRefusesAnythingAroundIt(string $rule, string $value): void
    {
        foreach (["$value\n", "\n$value", " $value", "$value ", "$value\0", "$value\r\n"] as $bad) {
            self::assertFalse(Field::is($rule, $bad), json_encode($bad).' is not a '.$rule);
        }
        self::assertFalse(Field::is($rule, ''));
    }

    #[DataProvider('good')]
    public function testOnlyAStringIsAField(string $rule, string $value): void
    {
        foreach ([null, 42, 4.2, true, [$value], new \stdClass()] as $bad) {
            self::assertFalse(Field::is($rule, $bad));
        }
    }

    /** @return iterable<string, array{string, string}> */
    public static function bad(): iterable
    {
        yield 'address without 0x' => [Field::ADDRESS, substr(self::ADDRESS, 2)];
        yield 'address too short' => [Field::ADDRESS, substr(self::ADDRESS, 0, -1)];
        yield 'address not hex' => [Field::ADDRESS, '0x'.str_repeat('zz', 20)];
        yield 'address 0X' => [Field::ADDRESS, '0X'.substr(self::ADDRESS, 2)];
        yield 'uint256 leading zero' => [Field::UINT256, '010'];
        yield 'uint256 negative' => [Field::UINT256, '-1'];
        yield 'uint256 hex' => [Field::UINT256, '0x10'];
        yield 'uint256 exponent' => [Field::UINT256, '1e3'];
        yield 'uint256 too long' => [Field::UINT256, str_repeat('9', 79)];
        yield 'uint256 other digits' => [Field::UINT256, '١٢٣'];
        yield 'amount zero' => [Field::AMOUNT, '0'];
        yield 'amount decimal' => [Field::AMOUNT, '1.5'];
        yield 'timestamp too long' => [Field::TIMESTAMP, str_repeat('9', 20)];
        yield 'payment id with a slash' => [Field::PAYMENT_ID, 'a/../b'];
        yield 'payment id too long' => [Field::PAYMENT_ID, str_repeat('a', 129)];
        yield 'evm network zero' => [Field::EVM_NETWORK, 'eip155:0'];
        yield 'evm network solana' => [Field::EVM_NETWORK, 'solana:x'];
        yield 'base58 with a zero' => [Field::BASE58, str_repeat('0', 44)];
        yield 'hash upper case' => [Field::HASH, str_repeat('0F', 32)];
    }

    #[DataProvider('bad')]
    public function testRefusesAnotherSpelling(string $rule, string $value): void
    {
        self::assertFalse(Field::is($rule, $value));
    }

    public function testNamesTheFirstFieldThatIsWrong(): void
    {
        $rules = ['from' => Field::ADDRESS, 'value' => Field::UINT256, 'nonce' => Field::BYTES32];
        $data = ['from' => self::ADDRESS, 'value' => '10', 'nonce' => '0x'.str_repeat('00', 32)];
        self::assertNull(Field::first($rules, $data));
        self::assertSame('value', Field::first($rules, ['value' => "10\n"] + $data));
        self::assertSame('nonce', Field::first($rules, ['from' => self::ADDRESS, 'value' => '10']), 'a missing field is wrong');
        self::assertSame('from', Field::first($rules, []));
    }

    public function testARuleThatDoesNotExistIsAMistakeNotARefusal(): void
    {
        // A typo in a rule name must not quietly refuse (or accept) every value.
        $this->expectException(\LogicException::class);
        Field::is('adress', self::ADDRESS);
    }
}
