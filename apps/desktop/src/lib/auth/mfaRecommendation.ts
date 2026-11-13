const RECOMMENDATION_KEY = "dbx-mfa-recommendation-dismissed";

function recommendationStore(admin: boolean): Storage | undefined {
  try {
    return admin ? window.sessionStorage : window.localStorage;
  } catch {
    return undefined;
  }
}

export function mfaRecommendationDismissed(userId: string, admin: boolean): boolean {
  try {
    return recommendationStore(admin)?.getItem(`${RECOMMENDATION_KEY}:${userId}`) === "1";
  } catch {
    return false;
  }
}

export function dismissMfaRecommendation(userId: string, admin: boolean): void {
  try {
    recommendationStore(admin)?.setItem(`${RECOMMENDATION_KEY}:${userId}`, "1");
  } catch {
    return;
  }
}
