(function () {
  const scoreWeights = {
    attackVector: {
      network: 0.85,
      adjacent: 0.62,
      local: 0.55,
      physical: 0.2
    },
    attackComplexity: {
      high: 0.44,
      low: 0.77
    },
    userInteraction: {
      none: 0.85,
      required: 0.62
    },
    scope: {
      changed: 7.52,
      unchanged: 6.42
    },
    privilegesRequired: {
      changed: {
        high: 0.5,
        low: 0.68,
        none: 0.85
      },
      unchanged: {
        high: 0.27,
        low: 0.62,
        none: 0.85
      }
    },
    confidentiality: {
      high: 0.56,
      low: 0.22,
      none: 0
    },
    integrity: {
      high: 0.56,
      low: 0.22,
      none: 0
    },
    availability: {
      high: 0.56,
      low: 0.22,
      none: 0
    },
    remediationLevel: {
      officialFix: 0.95,
      temporaryFix: 0.96,
      unavailable: 1,
      workaround: 0.97,
      notDefined: 1
    }
  };

  function calculateScore (inputs) {
    const metrics = {
      attackVector: scoreWeights.attackVector[inputs.attackVector],
      attackComplexity: scoreWeights.attackComplexity[inputs.attackComplexity],
      privilegesRequired: scoreWeights.privilegesRequired[inputs.scope][inputs.privilegesRequired],
      userInteraction: scoreWeights.userInteraction[inputs.userInteraction],
      scope: scoreWeights.scope[inputs.scope],
      confidentiality: scoreWeights.confidentiality[inputs.confidentiality],
      integrity: scoreWeights.integrity[inputs.integrity],
      availability: scoreWeights.availability[inputs.availability]
    };

    // Stolen from actuall CVSS calculation on https://www.first.org/cvss/calculator/3.1
    const exploitabilityCoefficient = 8.22;
    const scopeCoefficient = 1.08;
    const iss = (1 - ((1 - metrics.confidentiality) * (1 - metrics.integrity) * (1 - metrics.availability)));
    const impact = (metrics.scope === 'unchanged') ? (metrics.scope * iss) : (metrics.scope * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15));
    const exploitability = exploitabilityCoefficient * metrics.attackVector * metrics.attackComplexity * metrics.privilegesRequired * metrics.userInteraction;

    return (impact <= 0) ? 0 : ((metrics.scope === 'unchanged') ? (Math.min((exploitability + impact), 10)) : (Math.min(scopeCoefficient * (exploitability + impact), 10)));
  }

  console.log('Example CVSS: ', calculateScore({
    attackVector: 'physical',
    attackComplexity: 'high',
    scope: 'changed',
    userInteraction: 'none',
    privilegesRequired: 'none',
    confidentiality: 'high',
    integrity: 'low',
    availability: 'low'
  }));
})();