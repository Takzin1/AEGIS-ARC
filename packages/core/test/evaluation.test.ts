import { describe, expect, it } from "vitest";
import {
  scoreBinaryDetection,
  scoreMultiAnswer,
  scoreThreatHunt,
  scoreMulticlass,
  scoreQueryExecutability,
} from "../src";

describe("paper-derived research scorecards (synthetic fixtures only)", () => {
  it("computes confusion-matrix metrics and never confuses FPR with 1-precision", () => {
    const score = scoreBinaryDetection([
      { expected: true, predicted: true },
      { expected: true, predicted: false },
      { expected: false, predicted: true },
      { expected: false, predicted: false },
      { expected: false, predicted: false },
    ]);
    expect(score).toMatchObject({ tp: 1, fn: 1, fp: 1, tn: 2, samples: 5 });
    expect(score.precision).toBe(0.5);
    expect(score.recall).toBe(0.5);
    expect(score.falsePositiveRate).toBeCloseTo(1 / 3);
    expect(score.accuracy).toBe(0.6);
    expect(scoreBinaryDetection([]).accuracy).toBeNull();
    expect(scoreBinaryDetection([{ expected: true, predicted: true }]).falsePositiveRate).toBeNull();
  });

  it("uses exact-set scoring for CyberSOCEval-style multiple-answer questions", () => {
    const score = scoreMultiAnswer([
      { id: "q1", expectedChoices: ["A", "B"], predictedChoices: ["B", "A"] },
      { id: "q2", expectedChoices: ["B"], predictedChoices: ["B", "B"] },
      { id: "q3", expectedChoices: ["B"], predictedChoices: ["B", "C"] },
    ]);
    expect(score).toMatchObject({ correct: 1, total: 3, invalidDuplicatePredictions: 1 });
    expect(score.exactSetAccuracy).toBeCloseTo(1 / 3);
    expect(() => scoreMultiAnswer([
      { id: "q1", expectedChoices: ["A"], predictedChoices: [] },
      { id: "q1", expectedChoices: ["A"], predictedChoices: [] },
    ])).toThrow(/Duplicate question/);
    expect(scoreMultiAnswer([]).exactSetAccuracy).toBeNull();
  });

  it("measures narrative step coverage rather than raw timestamp recall", () => {
    const result = scoreThreatHunt([
      {
        id: "campaign-1",
        steps: [
          { id: "initial-access", eligibleTimestamps: ["t1", "t2"] },
          { id: "execution", eligibleTimestamps: ["t3"] },
          { id: "not-coverable", eligibleTimestamps: [] },
        ],
        observedTimestamps: ["t1", "t2", "t3", "noise", "t1"],
        submittedTimestamps: ["t2", "noise"],
        queryCount: 10,
      },
      {
        id: "campaign-2",
        steps: [{ id: "persistence", eligibleTimestamps: ["t4"] }],
        observedTimestamps: ["t4"],
        submittedTimestamps: ["t4"],
        queryCount: 51,
      },
    ]);
    expect(result.meanStepCoverage).toBe(0.75); // (1/2 + 1) / 2
    expect(result.totalCorrectFlagsObserved).toBe(4);
    expect(result.totalCorrectFlagsSubmitted).toBe(2);
    expect(result.overBudgetEpisodes).toBe(1);
    expect(result.perEpisode[0]).toMatchObject({ eligibleSteps: 2, coveredSteps: 1, coverage: 0.5 });
    expect(result.perEpisode[1]!.withinQueryBudget).toBe(false);
  });

  it("excludes empty hunt episodes from the mean and validates ids/query limits", () => {
    expect(scoreThreatHunt([{ id: "empty", steps: [], submittedTimestamps: [], observedTimestamps: [], queryCount: 0 }]).meanStepCoverage).toBeNull();
    expect(() => scoreThreatHunt([{ id: "bad", steps: [], submittedTimestamps: [], observedTimestamps: [], queryCount: -1 }])).toThrow(/query count/);
    expect(() => scoreThreatHunt([], -1)).toThrow(/budget/);
  });

  it("scores multiclass resolution codes separately from threat detection", () => {
    const result = scoreMulticlass([
      { expected: "benign", predicted: "benign" },
      { expected: "malicious", predicted: "malicious" },
      { expected: "benign", predicted: "malicious" },
    ], ["benign", "malicious"]);
    expect(result.accuracy).toBeCloseTo(2 / 3);
    expect(result.macroRecall).toBeCloseTo(0.75);
    expect(result.macroF1).toBeCloseTo(2 / 3);
    expect(() => scoreMulticlass([{ expected: "unknown", predicted: "benign" }], ["benign"])).toThrow(/Unknown/);
  });

  it("calculates actual syntax/parser executability rate, not BLEU similarity", () => {
    expect(scoreQueryExecutability([{ executableWithoutModification: true }, { executableWithoutModification: false }]))
      .toEqual({ tested: 2, executable: 1, rate: 0.5 });
    expect(scoreQueryExecutability([]).rate).toBeNull();
  });
});
