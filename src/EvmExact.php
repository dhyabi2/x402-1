<?php

declare(strict_types=1);

namespace Quebracho\X402;

use Psr\Clock\ClockInterface;

/**
 * The `exact` scheme on EVM chains: an EIP-3009 TransferWithAuthorization.
 */
final class EvmExact implements Scheme, SpendsOnce, Expires, AddressForm, VetsOffers
{
    /** Seconds a signature must still be valid for when it is settled, so it does not expire on its way into a block. */
    public const int SLACK = 6;

    /** An EIP-3009 authorization's fields, each in its one spelling (Field): anything else is invalid_payload. */
    private const array AUTHORIZATION = ['from' => Field::ADDRESS, 'to' => Field::ADDRESS, 'nonce' => Field::BYTES32, 'value' => Field::UINT256, 'validAfter' => Field::TIMESTAMP, 'validBefore' => Field::TIMESTAMP];

    /**
     * @param ?Signer                      $buyer
     *                                            Needed to pay; a seller that only verifies passes none
     * @param ClockInterface|\Closure|null $clock
     *                                            Returns the current Unix time; tests pin it
     */
    public function __construct(
        private readonly ?Signer $buyer = null,
        private readonly ClockInterface|\Closure|null $clock = null,
    ) {
    }

    public function supports(string $network): bool
    {
        return str_starts_with($network, 'eip155:');
    }

    public function pay(array $required, array $req): array
    {
        $buyer = $this->buyer ?? throw new \LogicException('Paying needs a buyer key.');

        return Authorization::pay($buyer, $required, $req, $this->now());
    }

    public function verify(array $payment, array $req): ?string
    {
        $auth = $payment['payload']['authorization'] ?? null;
        $signature = $payment['payload']['signature'] ?? null;
        $accepted = $payment['accepted'] ?? [];
        $now = $this->now();

        // Reason codes from the x402 v2 spec §9; clients match on them.
        return match (true) {
            !is_array($auth) || !is_string($signature) || !is_array($accepted) => 'invalid_payload',
            // One spelling per value: the encoder reads "0xAB", "0xab" and "ab" as
            // the same bytes, so a looser format would let one signature claim
            // several deliveries (Settlement::key) or reach the encoder malformed.
            !self::canonical($auth, $signature) => 'invalid_payload',
            ($payment['x402Version'] ?? null) !== 2 => 'invalid_x402_version',
            ($accepted['scheme'] ?? null) !== 'exact' => 'invalid_scheme',
            ($accepted['network'] ?? null) !== $req['network'] => 'invalid_network',
            empty($req['extra']['name']) || empty($req['extra']['version']) => 'invalid_payment_requirements',
            // An offer that charges nothing (zero, empty, not a plain integer) is not a sale; Networks::requirements already refuses it.
            !Field::is(Field::AMOUNT, (string) ($req['amount'] ?? '')) => 'invalid_payment_requirements',
            // Our own offer names a token and a seller the encoder can read: a bad one is our mistake, not the buyer's.
            !Field::is(Field::ADDRESS, $req['asset'] ?? null) || !Field::is(Field::ADDRESS, $req['payTo'] ?? null) => 'invalid_payment_requirements',
            // The buyer echoes the offer it took; a different echo is not that offer.
            0 !== strcasecmp((string) ($accepted['asset'] ?? ''), $req['asset'])
              || 0 !== strcasecmp((string) ($accepted['payTo'] ?? ''), $req['payTo'])
              || (string) ($accepted['amount'] ?? '') !== (string) $req['amount'] => 'invalid_payload',
            0 !== strcasecmp((string) ($auth['to'] ?? ''), $req['payTo']) => 'invalid_exact_evm_payload_recipient_mismatch',
            (string) ($auth['value'] ?? '') !== (string) $req['amount'] => 'invalid_exact_evm_payload_authorization_value_mismatch',
            (int) ($auth['validAfter'] ?? PHP_INT_MAX) > $now => 'invalid_exact_evm_payload_authorization_valid_after',
            // Slack so it does not expire on its way into a block, as the reference facilitator does.
            (int) ($auth['validBefore'] ?? 0) < $now + self::SLACK => 'invalid_exact_evm_payload_authorization_valid_before',
            // No longer than the offer allows (+60 s clock skew): bounds replay windows and claim storage.
            (int) $auth['validBefore'] > $now + (int) ($req['maxTimeoutSeconds'] ?? 0) + 60 => 'invalid_exact_evm_payload_authorization_valid_before',
            0 !== strcasecmp((string) Signer::recover(Authorization::digest($req, $auth), $signature), (string) ($auth['from'] ?? '')) => 'invalid_exact_evm_payload_signature',
            default => null,
        };
    }

    private static function canonical(array $auth, string $signature): bool
    {
        return null === Field::first(self::AUTHORIZATION, $auth) && Field::is(Field::SIGNATURE, $signature);
    }

    public function payer(array $payment): ?string
    {
        $from = $payment['payload']['authorization']['from'] ?? null;

        return is_string($from) ? $from : null;
    }

    /**
     * Network, payer and EIP-3009 nonce: re-signing the same nonce must not buy a second delivery.
     */
    public function spent(array $payment): ?array
    {
        $auth = $payment['payload']['authorization'] ?? null;

        return is_array($auth) ? [$payment['accepted']['network'] ?? '', strtolower((string) ($auth['from'] ?? '')), strtolower((string) ($auth['nonce'] ?? ''))] : null;
    }

    public function expiresAt(array $payment): ?int
    {
        $until = $payment['payload']['authorization']['validBefore'] ?? null;

        return is_numeric($until) ? (int) $until : null;
    }

    public function tooShortFor(array $payment, int $seconds): ?string
    {
        // verify() passed, so validBefore is a canonical decimal; same clock as verify().
        return (int) $this->expiresAt($payment) - $this->now() < $seconds + self::SLACK ? 'invalid_exact_evm_payload_authorization_valid_before' : null;
    }

    public function valid(string $address): bool
    {
        return Field::is(Field::ADDRESS, $address);
    }

    public function spell(string $address): string
    {
        return Signer::checksum($address);
    }

    public function same(string $a, string $b): bool
    {
        return 0 === strcasecmp($a, $b);
    }

    public function signable(array $req, array $token): bool
    {
        // Canonical only: Eip712 pads and strips 0x, so "0330…" or "0x000330…"
        // would sign to the same address that screening was shown in another form.
        return is_string($req['payTo'] ?? null) && $this->valid($req['payTo'])
            // Another EIP-712 domain would sign for a token we did not mean.
            && ($req['extra']['name'] ?? null) === ($token['extra']['name'] ?? false)
            && ($req['extra']['version'] ?? null) === ($token['extra']['version'] ?? false);
    }

    /**
     * The clock verify() uses; tooShortFor() reads the same one.
     */
    public function now(): int
    {
        return Clock::now($this->clock);
    }
}
