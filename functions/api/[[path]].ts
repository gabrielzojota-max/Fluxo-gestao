export const onRequest = async ({ request }: { request: Request }): Promise<Response> => {
  const target = new URL(request.url);
  target.protocol = "https:";
  target.hostname = "fluxo-gestao-api.equipe-rec.workers.dev";
  target.port = "";
  return fetch(new Request(target.toString(), request));
};
