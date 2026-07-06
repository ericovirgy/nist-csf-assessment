"""
assess.py — Avaliação de maturidade NIST Cybersecurity Framework 2.0

Lê um ficheiro YAML com pontuações por subcategoria (0-4) e produz:
  1. Relatório Markdown com pontuações médias por Função e nível global
  2. Gráfico radar PNG com as 6 Funções do CSF 2.0
  3. Lista priorizada de áreas críticas com sugestões de remediação

Uso: python assess.py --input sample_input.yaml --output report/
"""

import argparse
import os
import sys
from datetime import datetime
from pathlib import Path

import yaml
import matplotlib
matplotlib.use("Agg")  # Modo sem ecrã (headless) para ambientes de servidor
import matplotlib.pyplot as plt
import numpy as np

# ---------------------------------------------------------------------------
# Estrutura oficial do NIST CSF 2.0 (aproximada — verificar em nist.gov/cyberframework)
# ---------------------------------------------------------------------------
CSF_STRUCTURE = {
    "GOVERN": {
        "description": "Establish and monitor the organization's cybersecurity risk management strategy, expectations, and policy",
        "abbreviation": "GV",
        "categories": {
            "GV.OC": {
                "name": "Organizational Context",
                "subcategories": {
                    "GV.OC-01": "The organizational mission is understood and informs cybersecurity risk management",
                    "GV.OC-02": "Internal and external stakeholder needs, expectations, and requirements are understood",
                    "GV.OC-03": "Legal, regulatory, and contractual requirements regarding cybersecurity are understood",
                    "GV.OC-04": "Critical objectives, capabilities, and services are understood",
                    "GV.OC-05": "Outcomes, capabilities, and services that the organization depends on are understood",
                },
            },
            "GV.RM": {
                "name": "Risk Management Strategy",
                "subcategories": {
                    "GV.RM-01": "Risk management objectives are established and agreed to by organizational stakeholders",
                    "GV.RM-02": "Risk appetite and risk tolerance statements are established and communicated",
                    "GV.RM-03": "Cybersecurity risk management activities and outcomes are included in enterprise risk management processes",
                    "GV.RM-04": "Strategic direction that describes appropriate risk response options is established",
                    "GV.RM-05": "Lines of communication across the organization are established for cybersecurity risks",
                    "GV.RM-06": "A standardized method for calculating, documenting, categorizing, and prioritizing cybersecurity risks is established",
                    "GV.RM-07": "Strategic opportunities are characterized and included in cybersecurity risk discussions",
                },
            },
            "GV.RR": {
                "name": "Roles, Responsibilities, and Authorities",
                "subcategories": {
                    "GV.RR-01": "Organizational leadership is responsible and accountable for cybersecurity risk",
                    "GV.RR-02": "Roles and responsibilities for cybersecurity risk management are established",
                    "GV.RR-03": "Adequate resources are allocated commensurate with the cybersecurity risk strategy",
                    "GV.RR-04": "Cybersecurity is included in human resources practices",
                },
            },
            "GV.PO": {
                "name": "Policy",
                "subcategories": {
                    "GV.PO-01": "Policy for managing cybersecurity risks is established based on organizational context",
                    "GV.PO-02": "Policy for managing cybersecurity risks is reviewed, updated, communicated, and enforced",
                },
            },
            "GV.OV": {
                "name": "Oversight",
                "subcategories": {
                    "GV.OV-01": "Cybersecurity risk management strategy outcomes are reviewed to inform and adjust strategy",
                    "GV.OV-02": "The cybersecurity risk management strategy is reviewed and adjusted to ensure coverage of organizational requirements",
                    "GV.OV-03": "Organizational cybersecurity risk management performance is evaluated and reviewed",
                },
            },
            "GV.SC": {
                "name": "Cybersecurity Supply Chain Risk Management",
                "subcategories": {
                    "GV.SC-01": "A cybersecurity supply chain risk management program is established",
                    "GV.SC-02": "Cybersecurity requirements are established for suppliers and third-party partners",
                    "GV.SC-03": "Suppliers and third-party partners are prioritized by criticality",
                    "GV.SC-04": "Suppliers and third-party partners are assessed routinely to confirm they meet contractual requirements",
                    "GV.SC-05": "Requirements to address cybersecurity risks in supply chains are established",
                    "GV.SC-06": "Planning and due diligence are performed to reduce risks before entering formal supplier relationships",
                    "GV.SC-07": "The risks posed by a supplier, their products and services, and other third parties are understood",
                    "GV.SC-08": "Relevant suppliers and third-party partners are included in incident planning",
                    "GV.SC-09": "Supply chain security practices are integrated into cybersecurity and enterprise risk management programs",
                    "GV.SC-10": "Cybersecurity supply chain risk management plans include provisions for activities after the supplier relationship ends",
                },
            },
        },
    },
    "IDENTIFY": {
        "description": "Understand the organization's current cybersecurity risks to systems, people, assets, data, and capabilities",
        "abbreviation": "ID",
        "categories": {
            "ID.AM": {
                "name": "Asset Management",
                "subcategories": {
                    "ID.AM-01": "Inventories of hardware managed by the organization are maintained",
                    "ID.AM-02": "Inventories of software, services, and systems managed by the organization are maintained",
                    "ID.AM-03": "Representations of authorized network communication and data flows are maintained",
                    "ID.AM-04": "Inventories of services provided by suppliers are maintained",
                    "ID.AM-05": "Assets are prioritized based on classification, criticality, resources, and impact",
                    "ID.AM-07": "Inventories of data and corresponding metadata for designated data types are maintained",
                    "ID.AM-08": "Systems, hardware, software, services, and data are managed throughout their life cycles",
                },
            },
            "ID.RA": {
                "name": "Risk Assessment",
                "subcategories": {
                    "ID.RA-01": "Vulnerabilities in assets are identified, validated, and recorded",
                    "ID.RA-02": "Cyber threat intelligence is received from information sharing forums and sources",
                    "ID.RA-03": "Internal and external threats to the organization are identified and recorded",
                    "ID.RA-04": "Potential impacts and likelihoods of threats exploiting vulnerabilities are identified",
                    "ID.RA-05": "Threats, vulnerabilities, likelihoods, and impacts are used to understand inherent risk",
                    "ID.RA-06": "Risk responses are chosen, prioritized, planned, tracked, and communicated",
                    "ID.RA-07": "Changes and exceptions are managed",
                    "ID.RA-08": "Processes for receiving, analyzing, and responding to vulnerability disclosures are established",
                    "ID.RA-09": "The authenticity and integrity of hardware and software are assessed prior to acquisition",
                    "ID.RA-10": "Critical suppliers are assessed prior to acquisition",
                },
            },
            "ID.IM": {
                "name": "Improvement",
                "subcategories": {
                    "ID.IM-01": "Improvements are identified from evaluations",
                    "ID.IM-02": "Improvements are identified from security tests and exercises",
                    "ID.IM-03": "Improvements are identified from execution of operational processes",
                    "ID.IM-04": "Incident response plans and other cybersecurity plans incorporate lessons learned",
                },
            },
        },
    },
    "PROTECT": {
        "description": "Use safeguards to prevent or reduce cybersecurity risks",
        "abbreviation": "PR",
        "categories": {
            "PR.AA": {
                "name": "Identity Management, Authentication, and Access Control",
                "subcategories": {
                    "PR.AA-01": "Identities and credentials for authorized users, services, and hardware are managed by the organization",
                    "PR.AA-02": "Identities are proofed and bound to credentials based on the context of interactions",
                    "PR.AA-03": "Users, services, and hardware are authenticated",
                    "PR.AA-04": "Identity assertions are protected, conveyed, and verified",
                    "PR.AA-05": "Access permissions, entitlements, and authorizations are defined in a policy",
                    "PR.AA-06": "Physical access to assets is managed, monitored, and enforced commensurate with risk",
                },
            },
            "PR.AT": {
                "name": "Awareness and Training",
                "subcategories": {
                    "PR.AT-01": "Personnel are provided with awareness and training so they can perform their cybersecurity-related tasks",
                    "PR.AT-02": "Individuals in specialized roles are provided with awareness and training",
                },
            },
            "PR.DS": {
                "name": "Data Security",
                "subcategories": {
                    "PR.DS-01": "The confidentiality, integrity, and availability of data-at-rest are protected",
                    "PR.DS-02": "The confidentiality, integrity, and availability of data-in-transit are protected",
                    "PR.DS-10": "The confidentiality, integrity, and availability of data-in-use are protected",
                    "PR.DS-11": "Backups of data are created, protected, maintained, and tested",
                },
            },
            "PR.PS": {
                "name": "Platform Security",
                "subcategories": {
                    "PR.PS-01": "Configuration management practices are established and applied",
                    "PR.PS-02": "Software is maintained, replaced, and removed commensurate with risk",
                    "PR.PS-03": "Hardware is maintained, replaced, and removed commensurate with risk",
                    "PR.PS-04": "Log records are generated and made available for continuous monitoring",
                    "PR.PS-05": "Installation and execution of unauthorized software are prevented",
                    "PR.PS-06": "Secure software development practices are integrated into the software development life cycle",
                },
            },
            "PR.IR": {
                "name": "Technology Infrastructure Resilience",
                "subcategories": {
                    "PR.IR-01": "Networks and environments are protected from unauthorized logical access and usage",
                    "PR.IR-02": "The organization's technology assets are protected from environmental threats",
                    "PR.IR-03": "Mechanisms are implemented to achieve resilience requirements in normal and adverse situations",
                    "PR.IR-04": "Adequate resource capacity to ensure availability is maintained",
                },
            },
        },
    },
    "DETECT": {
        "description": "Find and analyze possible cybersecurity attacks and compromises",
        "abbreviation": "DE",
        "categories": {
            "DE.CM": {
                "name": "Continuous Monitoring",
                "subcategories": {
                    "DE.CM-01": "Networks and network services are monitored to find potentially adverse events",
                    "DE.CM-02": "The physical environment is monitored to find potentially adverse events",
                    "DE.CM-03": "Personnel activity and technology usage are monitored to find potentially adverse events",
                    "DE.CM-06": "External service provider activities and services are monitored to find potentially adverse events",
                    "DE.CM-09": "Computing hardware and software, runtime environments, and their data are monitored",
                },
            },
            "DE.AE": {
                "name": "Adverse Event Analysis",
                "subcategories": {
                    "DE.AE-02": "Potentially adverse events are analyzed to better characterize them",
                    "DE.AE-03": "Information is correlated from multiple sources",
                    "DE.AE-04": "The estimated impact and scope of adverse events are understood",
                    "DE.AE-06": "Information on adverse events is provided to authorized staff and tools",
                    "DE.AE-07": "Cyber threat intelligence and other contextual information are integrated into the analysis",
                    "DE.AE-08": "Incidents are declared when adverse events meet the defined incident criteria",
                },
            },
        },
    },
    "RESPOND": {
        "description": "Take action regarding a detected cybersecurity incident",
        "abbreviation": "RS",
        "categories": {
            "RS.MA": {
                "name": "Incident Management",
                "subcategories": {
                    "RS.MA-01": "The incident response plan is executed in coordination with relevant third parties once an incident is declared",
                    "RS.MA-02": "Incident reports are triaged and validated",
                    "RS.MA-03": "Incidents are categorized and prioritized",
                    "RS.MA-04": "Incidents are escalated or elevated as needed",
                    "RS.MA-05": "The criteria for initiating incident recovery are applied",
                },
            },
            "RS.AN": {
                "name": "Incident Analysis",
                "subcategories": {
                    "RS.AN-03": "Analysis is performed to establish what has taken place during an incident and the root cause of the incident",
                    "RS.AN-06": "Actions performed during an investigation are recorded",
                    "RS.AN-07": "Cause analysis is performed to determine the root cause of incidents",
                    "RS.AN-08": "An incident is characterized",
                },
            },
            "RS.CO": {
                "name": "Incident Response Reporting and Communication",
                "subcategories": {
                    "RS.CO-02": "Internal and external stakeholders are notified of incidents in a timely manner",
                    "RS.CO-03": "Information is shared with designated internal and external stakeholders",
                },
            },
            "RS.MI": {
                "name": "Incident Mitigation",
                "subcategories": {
                    "RS.MI-01": "Incidents are contained",
                    "RS.MI-02": "Incidents are eradicated",
                },
            },
        },
    },
    "RECOVER": {
        "description": "Restore assets and operations that were impacted by a cybersecurity incident",
        "abbreviation": "RC",
        "categories": {
            "RC.RP": {
                "name": "Incident Recovery Plan Execution",
                "subcategories": {
                    "RC.RP-01": "The recovery portion of the incident response plan is executed once initiated from the RESPOND function",
                    "RC.RP-02": "Recovery actions are selected, scoped, prioritized, and performed",
                    "RC.RP-03": "The integrity of backups and other restoration assets is verified before using them for restoration",
                    "RC.RP-04": "Critical mission functions and cybersecurity risk management are considered to establish post-incident norms",
                    "RC.RP-05": "The integrity of restored assets is verified, systems and services are restored",
                    "RC.RP-06": "The end of incident recovery is declared based on criteria, and documented",
                },
            },
            "RC.CO": {
                "name": "Incident Recovery Communication",
                "subcategories": {
                    "RC.CO-03": "Recovery activities and progress in restoring operational capabilities are communicated to stakeholders",
                    "RC.CO-04": "Public updates on incident recovery are shared using approved methods and messaging",
                },
            },
        },
    },
}

# Descrição dos níveis de maturidade (escala 0-4)
MATURITY_LEVELS = {
    0: ("Não Implementado", "Sem práticas ou controlos implementados"),
    1: ("Inicial",          "Práticas ad hoc, dependentes de indivíduos, sem consistência"),
    2: ("Gerenciado",       "Práticas documentadas e repetíveis ao nível da equipa"),
    3: ("Consistente",      "Práticas padronizadas, monitoradas e comunicadas transversalmente"),
    4: ("Otimizado",        "Melhoria contínua, adaptação proativa e benchmarking externo"),
}

# Sugestões de remediação por Função do CSF 2.0
REMEDIATION = {
    "GOVERN":   "Estabelecer uma política formal de governança de cibersegurança; designar CISO ou responsável equivalente; integrar riscos cibernéticos no ERM.",
    "IDENTIFY": "Inventariar todos os ativos (hardware, software, dados); implementar avaliações de risco regulares; gerir o risco na cadeia de fornecimento.",
    "PROTECT":  "Implementar MFA, princípio do menor privilégio, encriptação em repouso/trânsito e gestão de patches; formar todos os colaboradores.",
    "DETECT":   "Implementar SIEM, IDS/IPS e monitorização contínua; definir limiares de alerta e procedimentos de triagem de eventos.",
    "RESPOND":  "Desenvolver e testar plano de resposta a incidentes (IRP); definir RACI; realizar exercícios de simulação (tabletop).",
    "RECOVER":  "Criar e testar planos de recuperação e continuidade de negócio (BCP/DRP); garantir backups testados e off-site.",
}


# ---------------------------------------------------------------------------
# Carregamento e validação do ficheiro de entrada
# ---------------------------------------------------------------------------

def load_input(path: str) -> dict:
    """Carrega e valida o ficheiro YAML de avaliação."""
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)

    if not isinstance(data, dict):
        print("Erro: o ficheiro YAML deve conter um mapeamento no nível raiz.", file=sys.stderr)
        sys.exit(1)

    # Extrai os campos de metadados e os scores
    metadata = {
        "organization": data.get("organization", "Organização não especificada"),
        "assessor":     data.get("assessor", "Não especificado"),
        "date":         data.get("date", datetime.today().strftime("%Y-%m-%d")),
        "scope":        data.get("scope", "Não especificado"),
    }
    scores = data.get("scores", {})

    # Valida que cada pontuação está no intervalo 0-4
    for subcategory_id, score in scores.items():
        if not isinstance(score, (int, float)) or not (0 <= score <= 4):
            print(f"Aviso: pontuação inválida para {subcategory_id} ({score}); será usada 0.", file=sys.stderr)
            scores[subcategory_id] = 0

    return metadata, scores


# ---------------------------------------------------------------------------
# Cálculo de pontuações por Função e Categoria
# ---------------------------------------------------------------------------

def compute_scores(scores: dict) -> dict:
    """
    Calcula médias por subcategoria, categoria e função.
    Subcategorias não avaliadas recebem pontuação 0.
    """
    results = {}

    for function_name, function_data in CSF_STRUCTURE.items():
        function_scores = []
        categories_results = {}

        for cat_id, cat_data in function_data["categories"].items():
            cat_scores = []

            for subcat_id in cat_data["subcategories"]:
                # Subcategorias sem pontuação assumem 0 (não implementado)
                score = scores.get(subcat_id, 0)
                cat_scores.append({"id": subcat_id, "score": score, "description": cat_data["subcategories"][subcat_id]})
                function_scores.append(score)

            cat_avg = sum(s["score"] for s in cat_scores) / len(cat_scores) if cat_scores else 0
            categories_results[cat_id] = {
                "name":     cat_data["name"],
                "average":  round(cat_avg, 2),
                "scores":   cat_scores,
            }

        func_avg = sum(function_scores) / len(function_scores) if function_scores else 0
        results[function_name] = {
            "description": function_data["description"],
            "average":     round(func_avg, 2),
            "categories":  categories_results,
        }

    return results


def overall_maturity(results: dict) -> tuple[float, str, str]:
    """Calcula a maturidade global e retorna a pontuação, o nível e a descrição."""
    averages = [v["average"] for v in results.values()]
    overall = sum(averages) / len(averages) if averages else 0
    level_key = min(4, int(overall))
    level_name, level_desc = MATURITY_LEVELS[level_key]
    return round(overall, 2), level_name, level_desc


# ---------------------------------------------------------------------------
# Geração do relatório Markdown
# ---------------------------------------------------------------------------

def generate_markdown_report(metadata: dict, results: dict, output_dir: Path) -> Path:
    """Escreve o relatório de avaliação em formato Markdown."""
    overall_score, level_name, level_desc = overall_maturity(results)
    report_path = output_dir / "assessment_report.md"

    lines = [
        f"# Relatório de Avaliação NIST CSF 2.0",
        f"",
        f"| Campo | Valor |",
        f"|---|---|",
        f"| **Organização** | {metadata['organization']} |",
        f"| **Avaliador** | {metadata['assessor']} |",
        f"| **Data** | {metadata['date']} |",
        f"| **Âmbito** | {metadata['scope']} |",
        f"| **Pontuação Global** | **{overall_score:.2f} / 4.00** |",
        f"| **Nível de Maturidade** | **{level_name}** — {level_desc} |",
        f"",
        f"---",
        f"",
        f"## Resumo por Função CSF 2.0",
        f"",
        f"| Função | Descrição Curta | Média | Barra Visual |",
        f"|---|---|:---:|---|",
    ]

    for func_name, func_data in results.items():
        avg = func_data["average"]
        bar = generate_bar(avg)
        lines.append(f"| **{func_name}** | {func_data['description'][:60]}… | {avg:.2f} | {bar} |")

    lines += ["", "---", "", "## Detalhe por Função e Categoria", ""]

    for func_name, func_data in results.items():
        lines += [
            f"### {func_name}",
            f"*{func_data['description']}*",
            f"",
            f"**Média da Função: {func_data['average']:.2f} / 4.00**",
            f"",
        ]
        for cat_id, cat_data in func_data["categories"].items():
            lines += [
                f"#### {cat_id} — {cat_data['name']} (média: {cat_data['average']:.2f})",
                f"",
                f"| Subcategoria | Pontuação | Descrição |",
                f"|---|:---:|---|",
            ]
            for entry in cat_data["scores"]:
                score = entry["score"]
                lines.append(f"| `{entry['id']}` | {score} | {entry['description']} |")
            lines.append("")

    # Secção de remediação priorizada
    lines += ["---", "", "## Áreas Críticas e Remediação Priorizada", ""]
    sorted_funcs = sorted(results.items(), key=lambda x: x[1]["average"])

    for rank, (func_name, func_data) in enumerate(sorted_funcs, 1):
        level_key = min(4, int(func_data["average"]))
        level_label = MATURITY_LEVELS[level_key][0]
        lines += [
            f"### #{rank} — {func_name} (Média: {func_data['average']:.2f} | Nível: {level_label})",
            f"",
            f"> **Remediação sugerida:** {REMEDIATION[func_name]}",
            f"",
        ]

        # Lista as 3 subcategorias com piores pontuações dentro desta Função
        all_subcats = []
        for cat_data in func_data["categories"].values():
            all_subcats.extend(cat_data["scores"])
        worst = sorted(all_subcats, key=lambda x: x["score"])[:3]

        if worst:
            lines.append("Subcategorias mais críticas:")
            lines.append("")
            for entry in worst:
                lines.append(f"- `{entry['id']}` (pontuação: {entry['score']}) — {entry['description']}")
            lines.append("")

    lines += [
        "---",
        "",
        f"*Relatório gerado automaticamente em {datetime.now().strftime('%Y-%m-%d %H:%M')} por nist-csf-assessment.*",
        f"*⚠️ A estrutura do CSF 2.0 deve ser verificada na fonte oficial: [nist.gov/cyberframework](https://www.nist.gov/cyberframework)*",
    ]

    report_path.write_text("\n".join(lines), encoding="utf-8")
    return report_path


def generate_bar(score: float, max_score: float = 4.0, width: int = 10) -> str:
    """Gera uma barra de progresso em texto para o relatório Markdown."""
    filled = int((score / max_score) * width)
    return "█" * filled + "░" * (width - filled)


# ---------------------------------------------------------------------------
# Geração do gráfico radar PNG
# ---------------------------------------------------------------------------

def generate_radar_chart(results: dict, metadata: dict, output_dir: Path) -> Path:
    """Cria um gráfico radar (spider chart) com as 6 Funções do CSF 2.0."""
    function_names = list(results.keys())
    averages = [results[fn]["average"] for fn in function_names]

    # O gráfico radar requer que o último ponto seja igual ao primeiro (fechamento do polígono)
    num_vars = len(function_names)
    angles = np.linspace(0, 2 * np.pi, num_vars, endpoint=False).tolist()
    angles += angles[:1]
    averages_plot = averages + averages[:1]

    # Paleta de cores para cada Função
    function_colors = {
        "GOVERN":   "#2196F3",
        "IDENTIFY": "#4CAF50",
        "PROTECT":  "#FF9800",
        "DETECT":   "#9C27B0",
        "RESPOND":  "#F44336",
        "RECOVER":  "#009688",
    }
    fill_colors = [function_colors.get(fn, "#888888") for fn in function_names]

    fig, ax = plt.subplots(figsize=(9, 9), subplot_kw={"polar": True})
    fig.patch.set_facecolor("#1a1a2e")
    ax.set_facecolor("#16213e")

    # Linhas de referência para os 4 níveis de maturidade
    for level in [1, 2, 3, 4]:
        ref_values = [level] * num_vars + [level]
        ax.plot(angles, ref_values, linestyle="--", color="#ffffff22", linewidth=0.8)

    # Polígono preenchido com os scores
    ax.fill(angles, averages_plot, alpha=0.25, color="#4fc3f7")
    ax.plot(angles, averages_plot, color="#4fc3f7", linewidth=2, linestyle="solid")

    # Pontos individuais coloridos por Função
    for i, (angle, score, fn) in enumerate(zip(angles[:-1], averages, function_names)):
        ax.plot(angle, score, "o", markersize=10, color=function_colors.get(fn, "#4fc3f7"), zorder=5)

    # Rótulos dos eixos
    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(function_names, color="white", fontsize=11, fontweight="bold")
    ax.set_ylim(0, 4)
    ax.set_yticks([1, 2, 3, 4])
    ax.set_yticklabels(["1", "2", "3", "4"], color="#aaaaaa", fontsize=8)
    ax.tick_params(axis="x", pad=15)

    # Título e subtítulo
    overall_score, level_name, _ = overall_maturity(results)
    ax.set_title(
        f"Avaliação NIST CSF 2.0 — {metadata['organization']}\n"
        f"Maturidade Global: {overall_score:.2f}/4.00 ({level_name})",
        color="white",
        fontsize=13,
        fontweight="bold",
        pad=25,
    )

    # Legenda com pontuações por Função
    legend_text = "\n".join(
        f"{fn}: {results[fn]['average']:.2f}"
        for fn in function_names
    )
    fig.text(
        0.02, 0.02, legend_text,
        color="white", fontsize=8, va="bottom",
        bbox={"boxstyle": "round,pad=0.4", "facecolor": "#0d0d1e", "alpha": 0.8},
    )

    chart_path = output_dir / "radar_chart.png"
    plt.tight_layout()
    plt.savefig(chart_path, dpi=150, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close(fig)
    return chart_path


# ---------------------------------------------------------------------------
# Ponto de entrada CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Avaliação de maturidade NIST Cybersecurity Framework 2.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Exemplo: python assess.py --input sample_input.yaml --output report/",
    )
    parser.add_argument("--input",  required=True, help="Ficheiro YAML com as pontuações de avaliação")
    parser.add_argument("--output", required=True, help="Diretório para os ficheiros de saída")
    args = parser.parse_args()

    # Verifica e cria o diretório de saída
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"[1/3] A carregar avaliação de: {args.input}")
    metadata, scores = load_input(args.input)

    print("[2/3] A calcular pontuações...")
    results = compute_scores(scores)

    overall_score, level_name, level_desc = overall_maturity(results)
    print(f"      Maturidade global: {overall_score:.2f}/4.00 — {level_name}")

    print("[3/3] A gerar relatórios...")
    report_path = generate_markdown_report(metadata, results, output_dir)
    print(f"      Relatório Markdown: {report_path}")

    chart_path = generate_radar_chart(results, metadata, output_dir)
    print(f"      Gráfico radar:      {chart_path}")

    print(f"\nConcluído. Ficheiros em: {output_dir.resolve()}")
    print("[AVISO] A estrutura CSF 2.0 e aproximada. Verificar em: https://www.nist.gov/cyberframework")


if __name__ == "__main__":
    main()
