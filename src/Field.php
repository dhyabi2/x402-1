<?php

declare(strict_types=1);

namespace Quebracho\X402;

/**
 * The one spelling of each kind of value the library reads from outside: a buyer's payment, a seller's offer,
 * a facilitator's or a node's answer, a setting.
 *
 * Every rule takes a string, whole: nothing before it, nothing after it. A PCRE `$` also matches before a
 * final newline, so "0xabc…\n" used to pass a format check and then break the encoder, or go on as a second
 * spelling of the same value; the rules here end with `\z`, which does not. A value that is not a string (a
 * number, an array, null) is never a field.
 *
 * Why one spelling: the EIP-712 encoder reads "0xAB", "0xab" and "ab" as the same bytes, so a looser format
 * would let one signature be told apart as several payments (Settlement::key), or show screening an address
 * in one form and sign for it in another.
 *
 * Use it for a scheme of your own too:
 *
 *     if (null !== $bad = Field::first(['from' => Field::ADDRESS, 'nonce' => Field::BYTES32], $auth)) {
 *         return 'invalid_payload';
 *     }
 */
final class Field
{
    /** An EVM address: 0x and 40 hex digits, in any case (EIP-55's case is a checksum, not another address). */
    public const string ADDRESS = 'address';
    /** 32 bytes as 0x and 64 hex digits: an EIP-3009 nonce, a transaction hash, an ABI word a node answers. */
    public const string BYTES32 = 'bytes32';
    /** An EOA signature, r ‖ s ‖ v: 0x and 130 hex digits. */
    public const string SIGNATURE = 'signature';
    /** An EVM private key: 0x and 64 hex digits. */
    public const string PRIVATE_KEY = 'private_key';
    /** A uint256 as a decimal string: 0, or up to 78 digits with no leading zero. No sign, no exponent, no hex. */
    public const string UINT256 = 'uint256';
    /** An amount in atomic units: a uint256 above zero. */
    public const string AMOUNT = 'amount';
    /** Unix seconds as a decimal string: 0, or up to 19 digits with no leading zero. */
    public const string TIMESTAMP = 'timestamp';
    /** A facilitator's payment id, safe in a URL path: letters, digits, _ and -, at most 128. */
    public const string PAYMENT_ID = 'payment_id';
    /** A CAIP-2 EVM network: eip155: and a chain id above zero. */
    public const string EVM_NETWORK = 'evm_network';
    /** A base58 key or hash of 32 bytes (Solana, NEAR): 32 to 44 base58 characters. */
    public const string BASE58 = 'base58';
    /** A SHA-256 as the library writes it: 64 lower-case hex digits, no prefix (a claim's key, a Casper package hash). */
    public const string HASH = 'hash';
    /** A job's id: 32 lower-case hex digits. */
    public const string JOB_ID = 'job_id';

    /** Each rule as a pattern: anchored at both ends (\A, \z), ASCII only (no /u, so \d and \w would be ASCII too). */
    private const array PATTERNS = [
        self::ADDRESS => '/\A0x[0-9a-fA-F]{40}\z/',
        self::BYTES32 => '/\A0x[0-9a-fA-F]{64}\z/',
        self::SIGNATURE => '/\A0x[0-9a-fA-F]{130}\z/',
        self::PRIVATE_KEY => '/\A0x[0-9a-fA-F]{64}\z/',
        self::UINT256 => '/\A(?:0|[1-9][0-9]{0,77})\z/',
        self::AMOUNT => '/\A[1-9][0-9]{0,77}\z/',
        self::TIMESTAMP => '/\A(?:0|[1-9][0-9]{0,18})\z/',
        self::PAYMENT_ID => '/\A[A-Za-z0-9_-]{1,128}\z/',
        self::EVM_NETWORK => '/\Aeip155:[1-9][0-9]*\z/',
        self::BASE58 => '/\A[1-9A-HJ-NP-Za-km-z]{32,44}\z/',
        self::HASH => '/\A[0-9a-f]{64}\z/',
        self::JOB_ID => '/\A[0-9a-f]{32}\z/',
    ];

    /**
     * Whether $value is a string in the rule's one spelling.
     *
     * @param string $rule one of this class's constants
     *
     * @throws \LogicException when there is no such rule: a typo must not refuse (or accept) every value quietly
     */
    public static function is(string $rule, mixed $value): bool
    {
        $pattern = self::PATTERNS[$rule] ?? throw new \LogicException("No such field rule: $rule.");

        return \is_string($value) && 1 === preg_match($pattern, $value);
    }

    /**
     * The first field of $rules that $data does not hold in its one spelling (a missing one included), or NULL
     * when every field is good.
     *
     * @param array<string, string> $rules field name => rule
     * @param array<mixed>          $data
     */
    public static function first(array $rules, array $data): ?string
    {
        foreach ($rules as $name => $rule) {
            if (!self::is($rule, $data[$name] ?? null)) {
                return $name;
            }
        }

        return null;
    }
}
