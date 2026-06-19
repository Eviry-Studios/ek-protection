# Como instalar o EK-Protection

Guia rápido para instalar o antivírus EK-Protection na sua máquina Linux.

---

## Passo 1 — Abra o terminal

No seu Linux, abra o aplicativo "Terminal" (ou aperte `Ctrl+Alt+T`).

## Passo 2 — Cole o comando de instalação

Copie e cole exatamente este comando, depois aperte Enter:

```bash
curl -fsSL https://raw.githubusercontent.com/Eviry-Studios/ek-protection/main/install.sh | sudo bash
```

O sistema vai pedir sua senha de usuário (a mesma que você usa para instalar programas). Digite e aperte Enter — a senha não aparece na tela, isso é normal.

Aguarde alguns minutos. O instalador vai baixar e configurar tudo sozinho.

## Passo 3 — Configure sua senha do EK-Protection

Esta é uma senha **diferente** da senha do seu usuário — é a senha que protege o antivírus contra alterações indevidas.

```bash
sudo ekp auth setup
```

Vai pedir para você criar uma senha forte (mínimo 12 caracteres, com letra maiúscula, minúscula, número e símbolo). Anote essa senha em lugar seguro — sem ela você não consegue restaurar arquivos da quarentena nem alterar configurações críticas.

## Passo 4 — Ative o serviço

Isso faz o antivírus rodar sempre, mesmo depois de reiniciar o computador:

```bash
sudo systemctl enable --now ek-protection
```

## Passo 5 — Confirme que está funcionando

```bash
ekp status
```

Se aparecer `RUNNING` em verde, está tudo certo. ✅

---

## Comandos que você vai usar no dia a dia

| O que você quer fazer | Comando |
|---|---|
| Ver se está protegido | `ekp status` |
| Escanear a pasta Downloads ou um arquivo suspeito | `ekp scan file /caminho/do/arquivo` |
| Fazer um escaneamento rápido | `ekp scan quick` |
| Ver o que está em quarentena | `ekp quarantine list` |
| Ver os últimos avisos | `ekp logs tail` |

## Se algo der errado

Se aparecer algum aviso de ameaça e você não souber o que fazer, **não apague nada sozinho** — chame o suporte (Matheus/EviRyKorp) e mande o resultado deste comando:

```bash
ekp quarantine list
```

---

## Perguntas frequentes

**"Preciso instalar de novo depois que reiniciar o PC?"**
Não. Uma vez instalado e com `systemctl enable` ativado, ele liga sozinho sempre que o computador inicia.

**"O EK-Protection vai deixar meu computador lento?"**
Não. Ele foi desenhado para consumir o mínimo de CPU e memória possível, rodando em segundo plano.

**"Esqueci a senha do EK-Protection, e agora?"**
Avise o suporte. É possível resetar com acesso root à máquina, mas qualquer arquivo em quarentena nesse meio tempo só pode ser recuperado com a senha antiga ou com acesso físico/root à máquina.
