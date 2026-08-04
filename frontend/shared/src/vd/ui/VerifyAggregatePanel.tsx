import { useTranslation } from "react-i18next";
import type { EncryptedTally } from "../eth/types";
import { CodeBlock } from "./CodeBlock";

const SDK_PACKAGE = "@shutter-network/urban-verified-crypto";

type Props = {
  aggregate: EncryptedTally;
  onDownloadFixture: () => Promise<void>;
  downloading: boolean;
};

export function VerifyAggregatePanel({ aggregate, onDownloadFixture, downloading }: Props) {
  const { t } = useTranslation();
  const fixtureFilename = "aggregate-fixture.json";
  const scriptName = "verify-aggregate.js";

  const installCmd = `npm install ${SDK_PACKAGE} viem`;

  const scriptCode = [
    `const { initCurves, G1Point, G2Point, schnorrVerify, verifyBallot, sumCts } = require("${SDK_PACKAGE}");`,
    `const { readFileSync } = require("node:fs");`,
    `const { keccak256 } = require("viem");`,
    `const fromHex   = (h) => Uint8Array.from(Buffer.from(String(h).replace(/^0x/, ""), "hex"));`,
    `const g2FromHex = (h) => G2Point.fromBytes(fromHex(h));`,
    `const electionId32 = (id) => fromHex(BigInt(id).toString(16).padStart(64, "0"));`,
    `const makeWrVerifier = (pkWr) => {`,
    `  const wrVk = G1Point.fromBytes(pkWr);`,
    `  return (electionIdBytes, pseudonym, vk, att) => {`,
    `    if (electionIdBytes.length !== 32 || pseudonym.length !== 32 || vk.length !== 48) return false;`,
    `    try {`,
    `      let s = 0n; for (let i = 48; i < 80; i++) s = (s << 8n) + BigInt(att[i]);`,
    `      return schnorrVerify(wrVk, fromHex(keccak256(Buffer.concat([Buffer.from(electionIdBytes), Buffer.from(pseudonym), Buffer.from(vk)]))), { R: G1Point.fromBytes(att.subarray(0, 48)), s });`,
    `    } catch { return false; }`,
    `  };`,
    `};`,
    `async function main() {`,
    `  const f = JSON.parse(readFileSync("${fixtureFilename}", "utf8"));`,
    `  await initCurves();`,
    `  const mpk        = g2FromHex(f.mpkElectionG2);`,
    `  const wrVerifier = makeWrVerifier(fromHex(f.pkWrG1));`,
    `  const config     = { numCandidates: f.numCandidates, budget: f.budget, mode: f.mode ?? "exact", variant: f.variant ?? "A" };`,
    `  const electionIdBytes = electionId32(f.electionId);`,
    `  // Filter to locally valid ballots — mirrors what the on-chain aggregator does.`,
    `  const validBallots = f.ballots.filter((b) => {`,
    `    const res = verifyBallot(`,
    `      { electionId: electionIdBytes, pseudonym: fromHex(b.pseudonym), vk: fromHex(b.vk),`,
    `        ciphertexts: b.ciphertexts.map(({ c1, c2 }) => [fromHex(c1), fromHex(c2)]),`,
    `        zkProof: fromHex(b.zkProof), voterSignature: fromHex(b.voterSignature), wrAttestation: fromHex(b.wrAttestation) },`,
    `      config, mpk, wrVerifier,`,
    `    );`,
    `    return res.ok;`,
    `  });`,
    `  console.log(\`Using \${validBallots.length} of \${f.ballots.length} ballots (locally valid)\`);`,
    `  let ok = true;`,
    `  for (let j = 0; j < f.numCandidates; j++) {`,
    `    const sum = sumCts(validBallots.map((b) => ({ c1: g2FromHex(b.ciphertexts[j].c1), c2: g2FromHex(b.ciphertexts[j].c2) })));`,
    `    const pub = { c1: g2FromHex(f.aggregate[j].c1), c2: g2FromHex(f.aggregate[j].c2) };`,
    `    const match = sum.c1.equals(pub.c1) && sum.c2.equals(pub.c2);`,
    `    if (!match) ok = false;`,
    `    console.log(\`Candidate \${j}: \${match ? "✓ match" : "✗ mismatch"}\`);`,
    `  }`,
    `  console.log(ok ? "\\n✓ Aggregate verified" : "\\n✗ Aggregate mismatch");`,
    `  process.exit(ok ? 0 : 1);`,
    `}`,
    `main().catch((e) => { console.error(e); process.exit(2); });`,
  ].join("\n");

  const candidateLines = aggregate.aggregates
    .map((_, j) => `Candidate ${j}: ✓ match`)
    .join("\n");
  const expectedOutput = `Using N of N ballots (locally valid)\n${candidateLines}\n\n✓ Aggregate verified`;

  return (
    <div className="vpInline" role="region" aria-label={t("Aggregate verification guide")}>
      <div className="vpInlineHdr">
        <div>
          <div className="vpHeaderLabel">{t("Reproduce the homomorphic sum")}</div>
          <div className="vpHeaderSub">{t("{{n}} candidate ciphertexts", { n: aggregate.aggregates.length })}</div>
        </div>
      </div>
      <div className="vpBody">
        <p className="vpIntro">
          {t("Confirm that the on-chain aggregate is exactly the homomorphic sum of every accepted ballot · no ballot added twice, none omitted.")}
        </p>

        <div className="vpStep">
          <div className="vpStepNum">1</div>
          <div className="vpStepContent">
            <div className="vpStepTitle">{t("Download the aggregate fixture")}</div>
            <p className="vpStepDesc">
              {t("Contains every accepted ballot's ciphertext points and the published on-chain aggregate. All ballots are fetched from the chain · may take a moment.")}
            </p>
            <button
              type="button"
              className="vpDownloadBtn"
              onClick={() => void onDownloadFixture()}
              disabled={downloading}
            >
              <svg width="13" height="13" viewBox="0 0 13 13" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
                <path d="M6.5 1v8M3 6l3.5 3.5L10 6" />
                <path d="M1 11h11" />
              </svg>
              {downloading ? t("Fetching all ballots…") : fixtureFilename}
            </button>
          </div>
        </div>

        <div className="vpStep">
          <div className="vpStepNum">2</div>
          <div className="vpStepContent">
            <div className="vpStepTitle">{t("Install the Shutter crypto SDK")}</div>
            <CodeBlock>{installCmd}</CodeBlock>
          </div>
        </div>

        <div className="vpStep">
          <div className="vpStepNum">3</div>
          <div className="vpStepContent">
            <div className="vpStepTitle">{t("Write and run the verification script")}</div>
            <p className="vpStepDesc">
              {t("Save as")} <span className="mono">{scriptName}</span> {t("next to the fixture, then run:")}
            </p>
            <CodeBlock>{scriptCode}</CodeBlock>
            <CodeBlock>{`node ${scriptName}`}</CodeBlock>
            <div className="vpExpectedLabel">{t("Expected output")}</div>
            <pre className="vpExpectedOutput">{expectedOutput}</pre>
            <p className="vpStepDesc" style={{ marginTop: 8 }}>
              {t("Exit code 0 = aggregate matches. Exit code 1 = mismatch detected.")}
            </p>
          </div>
        </div>

        <div className="vpSection">
          <div className="vpSectionLabel">{t("WHAT'S BEING CHECKED")}</div>
          <div className="vpCheckList">
            <div className="vpCheckItem">
              <div className="vpCheckName">{t("Homomorphic sum")}</div>
              <div className="vpCheckDesc">
                {t("Each ballot ciphertext (c1, c2) is a BLS12-381 G2 point. Point-adding all per-candidate c1s gives the aggregate c1; same for c2. The result must equal the on-chain aggregate byte-for-byte.")}
              </div>
            </div>
            <div className="vpCheckItem">
              <div className="vpCheckName">{t("Only accepted ballots counted")}</div>
              <div className="vpCheckDesc">
                {t("The fixture includes only ballots whose ZK proofs passed on-chain. Any ballot rejected at submission is excluded from the sum.")}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
