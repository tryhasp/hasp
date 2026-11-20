import type { FieldPurpose, FormKind, FrameKind, PageSnap, FormClass, PathHint } from './types.ts';

export type ProblemReport = {
  frame: FrameKind;
  pathHint: PathHint;
  lang: string;
  forms: {
    kind: FormKind;
    confidence: number;
    evidence: readonly string[];
    fields: {
      purpose: FieldPurpose | 'unclassified';
      tag: string;
      type: string;
      name: string;
      domId: string;
      autocomplete: readonly string[];
      label: string;
      placeholder: string;
      ariaLabel: string;
      textSecurity: boolean;
      visible: boolean;
      maxlength: number | undefined;
    }[];
  }[];
};

export const buildProblemReport = (
  page: PageSnap,
  classes: readonly FormClass[],
): ProblemReport => ({
  frame: page.frame,
  pathHint: page.pathHint,
  lang: page.lang,
  forms: classes.map((c) => {
    const form = page.forms.find((f) => f.id === c.formId);
    const fields = page.fields.filter(
      (f) => form?.fieldIds.includes(f.id) === true && f.tag !== 'button',
    );
    return {
      kind: c.kind,
      confidence: c.confidence,
      evidence: c.evidence,
      fields: fields.map((f) => ({
        purpose: c.fields.find((a) => a.id === f.id)?.purpose ?? 'unclassified',
        tag: f.tag,
        type: f.type,
        name: f.name,
        domId: f.domId,
        autocomplete: f.autocomplete,
        label: f.label,
        placeholder: f.placeholder,
        ariaLabel: f.ariaLabel,
        textSecurity: f.textSecurity,
        visible: f.visible,
        maxlength: f.maxlength,
      })),
    };
  }),
});
