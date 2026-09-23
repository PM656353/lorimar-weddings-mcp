export class DurableObject<Env> {
  constructor(
    protected ctx: DurableObjectState,
    protected env: Env
  ) {}
}

export class WorkerEntrypoint {}
