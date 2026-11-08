/**
 * Research benchmark scoring primitives for AEGIS-ARC.
 *
 * These metrics consume ONLY pre-labelled, authorized, offline evaluation data.
 * They do not perform scanning, malware execution, SQL execution, or model inference.
 * Data from papers must not be mistaken for measurements of AEGIS-ARC.
 */
export interface BinaryExample {
  expected: boolean;
  predicted: boolean;
}

export interface BinaryDetectionScore {
  samples: number;
  tp: number;
  fp: number;
  tn: number;
  fn: number;
  accuracy: number | null;
  precision: number | null;
  recall: number | null;
  f1: number | null;
  falsePositiveRate: number | null;
  specificity: number | null;
}

/** Null means the metric's denominator is zero; never turn it into a misleading 0 or 1. */
function fraction(numerator: number, denominator: number): number | null {
  return denominator === 0 ? null : numerator / denominator;
}

export function scoreBinaryDetection(examples: readonly BinaryExample[]): BinaryDetectionScore {
  let tp = 0;
  let fp = 0;
  let tn = 0;
  let fn = 0;
  for (const item of examples) {
    if (item.expected && item.predicted) tp++;
    else if (!item.expected && item.predicted) fp++;
    else if (!item.expected && !item.predicted) tn++;
    else fn++;
  }
  const precision = fraction(tp, tp + fp);
  const recall = fraction(tp, tp + fn);
  return {
    samples: examples.length,
    tp, fp, tn, fn,
    accuracy: fraction(tp + tn, examples.length),
    precision, recall,
    f1: precision === null || recall === null ? null : fraction(2 * tp, 2 * tp + fp + fn),
    falsePositiveRate: fraction(fp, fp + tn),
    specificity: fraction(tn, fp + tn),
  };
}

/**
 * CyberSOCEval-inspired exact-set QA scoring.
 * A question is correct ONLY when every expected choice and no unexpected
 * choice appears. Duplicate answers from the model are treated as invalid.
 */
export interface MultiAnswerQuestion {
  id: string;
  expectedChoices: readonly string[];
  predictedChoices: readonly string[];
}
export interface MultiAnswerScore {
  total: number;
  correct: number;
  invalidDuplicatePredictions: number;
  exactSetAccuracy: number | null;
  perQuestion: readonly { id: string; correct: boolean }[];
}

export function scoreMultiAnswer(examples: readonly MultiAnswerQuestion[]): MultiAnswerScore {
  let correct = 0;
  let invalidDuplicatePredictions = 0;
  const ids = new Set<string>();
  const perQuestion: { id: string; correct: boolean }[] = [];
  for (const example of examples) {
    if (ids.has(example.id)) throw new Error("Duplicate question ID: " + example.id);
    ids.add(example.id);
    const expected = new Set(example.expectedChoices);
    const predicted = new Set(example.predictedChoices);
    const duplicatePrediction = predicted.size !== example.predictedChoices.length;
    if (duplicatePrediction) invalidDuplicatePredictions++;
    // Duplicate gold answer labels are a malformed benchmark, not a model failure.
    if (expected.size !== example.expectedChoices.length) {
      throw new Error("Duplicate reference choice in question: " + example.id);
    }
    const exact = !duplicatePrediction &&
      predicted.size === expected.size &&
      [...predicted].every((choice) => expected.has(choice));
    if (exact) correct++;
    perQuestion.push({ id: example.id, correct: exact });
  }
  return {
    total: examples.length,
    correct,
    invalidDuplicatePredictions,
    exactSetAccuracy: fraction(correct, examples.length),
    perQuestion,
  };
}

/**
 * Cyber Defense Benchmark-inspired *step coverage*, NOT event recall.
 * Each eligible narrative step is covered when at least one of that step's
 * ground-truth malicious timestamps was correctly submitted.
 *
 * Timestamps must be normalized upstream, preserving microsecond precision.
 * Excludes un-coverable steps with zero eligible timestamps; excludes empty
 * instances from the macro-average. Never send raw log rows into this scorer.
 */
export interface NarrativeStep {
  id: string;
  eligibleTimestamps: readonly string[];
}
export interface HuntEpisode {
  id: string;
  steps: readonly NarrativeStep[];
  /** Ground-truth flag timestamps returned by a query need not be submitted. */
  observedTimestamps: readonly string[];
  submittedTimestamps: readonly string[];
  queryCount: number;
}

export interface HuntEpisodeScore {
  id: string;
  eligibleSteps: number;
  coveredSteps: number;
  coverage: number | null;
  correctFlagsObserved: number;
  correctFlagsSubmitted: number;
  queryCount: number;
  withinQueryBudget: boolean;
}
export interface HuntScore {
  episodes: number;
  scoredEpisodes: number;
  meanStepCoverage: number | null;
  totalCorrectFlagsObserved: number;
  totalCorrectFlagsSubmitted: number;
  overBudgetEpisodes: number;
  perEpisode: readonly HuntEpisodeScore[];
}

export function scoreThreatHunt(episodes: readonly HuntEpisode[], maxQueries = 50): HuntScore {
  if (!Number.isInteger(maxQueries) || maxQueries < 0) throw new RangeError("Invalid query budget");
  const episodeIds = new Set<string>();
  const perEpisode: HuntEpisodeScore[] = [];
  for (const episode of episodes) {
    if (episodeIds.has(episode.id)) throw new Error("Duplicate episode: " + episode.id);
    episodeIds.add(episode.id);
    if (!Number.isInteger(episode.queryCount) || episode.queryCount < 0) {
      throw new RangeError("Invalid query count: " + episode.id);
    }
    const stepIds = new Set<string>();
    const eligible = episode.steps.filter((step) => {
      if (stepIds.has(step.id)) throw new Error("Duplicate step: " + step.id);
      stepIds.add(step.id);
      return step.eligibleTimestamps.length > 0;
    });
    const gold = new Set(eligible.flatMap((step) => [...step.eligibleTimestamps]));
    const submitted = new Set(episode.submittedTimestamps);
    const observed = new Set(episode.observedTimestamps);
    const coveredSteps = eligible.filter((step) => step.eligibleTimestamps.some((flag) => submitted.has(flag))).length;
    perEpisode.push({
      id: episode.id,
      eligibleSteps: eligible.length,
      coveredSteps,
      coverage: fraction(coveredSteps, eligible.length),
      correctFlagsObserved: [...observed].filter((flag) => gold.has(flag)).length,
      correctFlagsSubmitted: [...submitted].filter((flag) => gold.has(flag)).length,
      queryCount: episode.queryCount,
      withinQueryBudget: episode.queryCount <= maxQueries,
    });
  }
  const eligibleEpisodes = perEpisode.filter((item) => item.coverage !== null);
  return {
    episodes: episodes.length,
    scoredEpisodes: eligibleEpisodes.length,
    meanStepCoverage: eligibleEpisodes.length > 0
      ? eligibleEpisodes.reduce((sum, item) => sum + item.coverage!, 0) / eligibleEpisodes.length
      : null,
    totalCorrectFlagsObserved: perEpisode.reduce((sum, item) => sum + item.correctFlagsObserved, 0),
    totalCorrectFlagsSubmitted: perEpisode.reduce((sum, item) => sum + item.correctFlagsSubmitted, 0),
    overBudgetEpisodes: perEpisode.filter((item) => !item.withinQueryBudget).length,
    perEpisode,
  };
}

export interface ClassExample {
  expected: string;
  predicted: string;
}
export interface MulticlassScore {
  accuracy: number | null;
  macroPrecision: number | null;
  macroRecall: number | null;
  macroF1: number | null;
  perClass: readonly { label: string; support: number; precision: number | null; recall: number | null; f1: number | null }[];
}

/**
 * Macro scores over explicitly declared labels. Missing classes are excluded
 * from macro aggregation, rather than interpreting zero denominators as zero.
 */
export function scoreMulticlass(examples: readonly ClassExample[], labels: readonly string[]): MulticlassScore {
  if (new Set(labels).size !== labels.length || labels.length === 0) throw new Error("Labels must be unique and nonempty");
  const allowed = new Set(labels);
  for (const item of examples) {
    if (!allowed.has(item.expected) || !allowed.has(item.predicted)) throw new Error("Unknown class label");
  }
  const perClass = labels.map((label) => {
    const binary = scoreBinaryDetection(examples.map((item) => ({
      expected: item.expected === label, predicted: item.predicted === label,
    })));
    return {
      label,
      support: examples.filter((item) => item.expected === label).length,
      precision: binary.precision,
      recall: binary.recall,
      f1: binary.f1,
    };
  });
  function mean(field: "precision" | "recall" | "f1"): number | null {
    const defined = perClass.map((item) => item[field]).filter((x): x is number => x !== null);
    return defined.length ? defined.reduce((a, b) => a + b, 0) / defined.length : null;
  }
  return {
    accuracy: fraction(examples.filter((item) => item.expected === item.predicted).length, examples.length),
    macroPrecision: mean("precision"),
    macroRecall: mean("recall"),
    macroF1: mean("f1"),
    perClass,
  };
}

export interface QueryValidation {
  /** The query was actually tested against an authorized offline or staging parser. */
  executableWithoutModification: boolean;
}

export function scoreQueryExecutability(cases: readonly QueryValidation[]): {
  tested: number; executable: number; rate: number | null;
} {
  const executable = cases.filter((item) => item.executableWithoutModification).length;
  return { tested: cases.length, executable, rate: fraction(executable, cases.length) };
}
