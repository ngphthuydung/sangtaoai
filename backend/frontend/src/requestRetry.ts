export const MAX_AUTOMATIC_GATEWAY_RETRIES = 1;
export const GATEWAY_RETRY_DELAY_MS = 250;

export function isTransientGatewayResponse(
  response: Pick<Response, 'status' | 'headers'>,
): boolean {
  const contentType = response.headers.get('content-type') ?? '';
  return (
    [502, 503].includes(response.status) &&
    !contentType.toLowerCase().includes('application/json')
  );
}

export async function retryTransientGatewayRequest<ResponseType>(
  request: () => Promise<ResponseType>,
  isTransientGatewayResponse: (response: ResponseType) => boolean | Promise<boolean>,
  wait: (milliseconds: number) => Promise<void>,
): Promise<ResponseType> {
  let response = await request();

  for (let retry = 0; retry < MAX_AUTOMATIC_GATEWAY_RETRIES; retry += 1) {
    if (!(await isTransientGatewayResponse(response))) return response;
    await wait(GATEWAY_RETRY_DELAY_MS);
    response = await request();
  }

  return response;
}
