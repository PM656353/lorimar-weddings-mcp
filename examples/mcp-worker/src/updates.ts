import { z } from "zod";

// Deliberately excludes ownership, location, consent, financial, nested deletion,
// event dates, and booking fields. Values must come from the customer's request.
export const leadChanges = z.strictObject({
  first_name: z.string().trim().min(1).max(50).optional(),
  last_name: z.string().trim().min(1).max(50).optional(),
  guest_count: z.number().int().min(1).max(10000).optional(),
  additional_information: z.string().min(1).max(5000).optional(),
  contact_preference: z.enum(["Phone", "Email", "Text"]).optional()
});
export const contactChanges = z.strictObject({
  first_name: z.string().trim().min(1).max(50).optional(),
  last_name: z.string().trim().min(1).max(50).optional(),
  description: z.string().min(1).max(1000).optional()
});
export function parseChanges(resource: string, value: unknown) {
  const schema =
    resource === "leads"
      ? leadChanges
      : resource === "contacts"
        ? contactChanges
        : null;
  const parsed = schema?.safeParse(value);
  return parsed?.success && Object.keys(parsed.data).length > 0
    ? parsed.data
    : null;
}
