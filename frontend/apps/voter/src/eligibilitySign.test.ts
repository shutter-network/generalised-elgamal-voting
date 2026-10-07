import { describe, expect, it } from "vitest";
import { recoverMessageAddress } from "viem";

/** The chain-free challenge the wallet personal-signs — must be byte-identical to the
 * eligibility service's `challenge_message` (eligibility.py). */
function challengeMessage(eidHex: string, vkHex: string): string {
  return `Shutter Governance Protocol eligibility attestation\nelectionId: ${eidHex}\nvk: ${vkHex}`;
}

/** Cross-impl lock: recover the same address the Python fixture signed with
 * (tests/test_eligibility_service.py::test_challenge_message_fixture). If the message
 * bytes drift on either side, recovery yields the wrong address and both break. */
describe("eligibility challenge (EIP-191 personal-sign)", () => {
  it("recovers the Python fixture's signer address", async () => {
    const eid = ("0x" + "00".repeat(31) + "01") as `0x${string}`;
    const vk = ("0x" + "ab".repeat(48)) as `0x${string}`;
    const signature =
      ("0x73a3d985a6689ecec6c51423b78083973d40a13551b25dc7f4ad7026b2b80d76" +
        "60bd09c9826035423afc7d3a8b64f693e16b58b221be8890afaf914d41ce3c4c1b") as `0x${string}`;
    const addr = await recoverMessageAddress({ message: challengeMessage(eid, vk), signature });
    expect(addr).toBe("0x70997970C51812dc3A010C7d01b50e0d17dc79C8");
  });
});
