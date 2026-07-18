# Permission Set: TF4-SecReliabilityReadOnlyAudit

Tài liệu này chi tiết hóa quyền hạn của Permission Set `TF4-SecReliabilityReadOnlyAudit` được gán cho người dùng **nguyen**. Đây là tập hợp quyền phục vụ công tác giám sát bảo mật hạ tầng chuyên sâu và đánh giá độ tin cậy của toàn bộ hệ thống dự án TF4.

## 📄 Nội dung Policy (JSON)

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "InfrastructureReliabilityReadOnly",
            "Effect": "Allow",
            "Action": [
                "eks:Describe*",
                "eks:List*",
                "ec2:Describe*",
                "elasticloadbalancing:Describe*",
                "autoscaling:Describe*",
                "ecr:Describe*",
                "ecr:List*",
                "ecr:GetAuthorizationToken",
                "cloudwatch:*",
                "logs:*"
            ],
            "Resource": "*"
        },
        {
            "Sid": "SecurityAssessmentAndAuditTools",
            "Effect": "Allow",
            "Action": [
                "iam:Get*",
                "iam:List*",
                "access-analyzer:Get*",
                "access-analyzer:List*",
                "access-analyzer:ValidatePolicy",
                "secretsmanager:ListSecrets",
                "secretsmanager:DescribeSecret",
                "kms:ListKeys",
                "kms:DescribeKey",
                "securityhub:Get*",
                "securityhub:List*",
                "guardduty:Get*",
                "guardduty:List*",
                "wafv2:Get*",
                "wafv2:List*",
                "acm:DescribeCertificate",
                "acm:ListCertificates"
            ],
            "Resource": "*"
        },
        {
            "Sid": "AllowPortForwardingToApprovedBastion",
            "Effect": "Allow",
            "Action": [
                "ssm:StartSession"
            ],
            "Resource": [
                "arn:aws:ec2:us-east-1:511825856493:instance/i-072084d1cf0b2f1c9",
                "arn:aws:ssm:us-east-1::document/AWS-StartPortForwardingSession"
            ]
        },
        {
            "Sid": "AllowSessionDataChannelForOwnSessions",
            "Effect": "Allow",
            "Action": [
                "ssmmessages:OpenDataChannel"
            ],
            "Resource": [
                "arn:aws:ssm:us-east-1:511825856493:session/*"
            ]
        },
        {
            "Sid": "AllowManageOwnSessions",
            "Effect": "Allow",
            "Action": [
                "ssm:ResumeSession",
                "ssm:TerminateSession"
            ],
            "Resource": [
                "arn:aws:ssm:us-east-1:511825856493:session/*"
            ]
        },
        {
            "Sid": "AllowReadOnlySessionAndInstanceDiscovery",
            "Effect": "Allow",
            "Action": [
                "ssm:DescribeInstanceInformation",
                "ssm:DescribeSessions",
                "ssm:GetConnectionStatus",
                "ec2:DescribeInstances"
            ],
            "Resource": "*"
        },
        {
            "Sid": "AllowECRReadImages",
            "Effect": "Allow",
            "Action": [
                "ecr:DescribeImages",
                "ecr:DescribeRepositories",
                "ecr:BatchGetImage"
            ],
            "Resource": "arn:aws:ecr:us-east-1:511825856493:repository/techx-corp"
        }
    ]
}
```

---

## 🔍 Giải thích chi tiết Quyền hạn

Policy này gồm các Statements lớn phục vụ cho khía cạnh Giám sát hạ tầng, Đánh giá an toàn thông tin và Vận hành bảo mật:

### Statement 1: `InfrastructureReliabilityReadOnly` (Độ tin cậy hạ tầng - Read/Write Logs)

Nhóm quyền này cho phép người dùng giám sát toàn diện tình trạng sức khỏe, tính sẵn sàng của hạ tầng và quản lý logs:

* **Amazon EKS & EC2**: Liệt kê và mô tả chi tiết thông số của Kubernetes clusters, instances, vpc, subnets, và autoscaling.
* **Elastic Load Balancing (ELB)**: Theo dõi cân bằng tải để phát hiện hiện tượng quá tải hoặc tắc nghẽn traffic.
* **Amazon ECR**: Lấy authorization token và mô tả thông tin repositories để xác minh phiên bản container images đang chạy.
* **CloudWatch & Logs (`cloudwatch:*`, `logs:*`)**: Cấp quyền tối cao cho hệ thống logs và metrics, cho phép theo dõi dashboard, tạo alarm, phân tích log chuyên sâu qua CloudWatch Logs Insights mà không bị giới hạn quyền.

---

### Statement 2: `SecurityAssessmentAndAuditTools` (Công cụ đánh giá bảo mật)

Nhóm quyền này cho phép đội ngũ bảo mật cấu hình, theo dõi và đánh giá mức độ an toàn thông tin (Security posture) của toàn bộ tài khoản AWS:

* **IAM & Access Analyzer**: Đọc cấu hình phân quyền (`iam:Get*`, `iam:List*`) và kiểm tra tính hợp lệ của policy bằng Access Analyzer (`ValidatePolicy`), giúp phát hiện các cấu hình phân quyền sai lệch hoặc vi phạm chính sách bảo mật.
* **Secrets Manager & KMS**: Cho phép xem danh sách các secrets và mô tả các key mã hóa (`kms:DescribeKey`, `kms:ListKeys`) nhằm đánh giá mức độ tuân thủ quy tắc quản lý khóa mật mã và quản lý mật khẩu. *Lưu ý: Không được cấp quyền lấy giá trị secret hoặc giải mã dữ liệu.*
* **AWS Security Hub & GuardDuty**: Theo dõi các cảnh báo bảo mật, các mối đe dọa trực tuyến đã phát hiện trên hệ thống Cloud (`securityhub:Get*`, `guardduty:Get*`).
* **AWS WAFv2**: Xem thông tin cấu hình tường lửa ứng dụng web (`wafv2:Get*`, `wafv2:List*`) để xác định hệ thống có được bảo vệ chống lại các lỗ hổng OWASP Top 10 hay không.
* **AWS Certificate Manager (ACM)**: Đọc thông tin và trạng thái của các chứng chỉ SSL/TLS (`acm:DescribeCertificate`) nhằm tránh tình trạng chứng chỉ hết hạn gây gián đoạn dịch vụ.

---

### Các Statement liên quan tới SSM Session Manager (`AllowPortForwardingToApprovedBastion`, v.v.)

Cho phép người dùng thiết lập kết nối an sau và chuyển tiếp cổng (Port Forwarding Session) từ máy cá nhân thông qua Session Manager tới Bastion host được chỉ định (`i-072084d1cf0b2f1c9`), cũng như tự quản lý phiên kết nối SSM của mình.

---

### Statement: `AllowECRReadImages` (Đọc image từ ECR)

Cấp quyền cho phép mô tả hình ảnh container, mô tả repo và pull các container images từ AWS ECR repository `techx-corp`.

---
[⬅️ Quay lại thông tin user nguyen](README.md) | [🏡 Quay lại trang chủ IAM Docs](../../README.md)
