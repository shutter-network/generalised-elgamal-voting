import { describe, expect, it } from "vitest";
import { recoverMessageAddress } from "viem";

/** The chain-free challenge the wallet personal-signs — must be byte-identical to the
 * eligibility service's `challenge_message` (eligibility.py). */
function challengeMessage(eidHex: string, vkHex: string): string {
  return `GEG eligibility attestation\nelectionId: ${eidHex}\nvk: ${vkHex}`;
}

/** Cross-impl lock: recover the same address the Python fixture signed with
 * (tests/test_eligibility_service.py::test_challenge_message_fixture). If the message
 * bytes drift on either side, recovery yields the wrong address and both break. */
describe("eligibility challenge (EIP-191 personal-sign)", () => {
  it("recovers the Python fixture's signer address", async () => {
    const eid = ("0x" + "00".repeat(31) + "01") as `0x${string}`;
    const vk = ("0x" + "ab".repeat(48)) as `0x${string}`;
    const signature =
      ("0x6095900a3840d0fb149f73cda9d07944005415ae6ba6cc0fd035030357e16a87" +
        "5e4fd6d174cb3f47b61c15f04107d5eb020d04bc9b5be8e2cb1166406a49f1c61c") as `0x${string}`;
    const addr = await recoverMessageAddress({ message: challengeMessage(eid, vk), signature });
    expect(addr).toBe("0x70997970C51812dc3A010C7d01b50e0d17dc79C8");
  });
});
