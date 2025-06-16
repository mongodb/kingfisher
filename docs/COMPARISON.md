### Runtime Comparison (seconds)
*Lower runtimes are better.*
| Repository | Kingfisher Runtime | TruffleHog Runtime | GitLeaks Runtime | detect-secrets Runtime |
|------------|--------------------|--------------------|------------------|------------------------|
| croc | 2.64 | 10.36 | 3.10 | 0.16 |
| rails | 8.75 | 24.19 | 24.24 | 0.48 |
| ruby | 22.93 | 132.68 | 61.37 | 0.79 |
| gitlab | 135.41 | 325.93 | 350.84 | 5.04 |
| django | 6.91 | 227.63 | 59.50 | 0.61 |
| lucene | 15.62 | 89.11 | 76.24 | 0.66 |
| mongodb | 25.37 | 174.93 | 175.80 | 2.74 |
| linux | 205.19 | 597.51 | 548.96 | 5.49 |
| typescript | 64.99 | 183.04 | 232.34 | 4.23 |

### Validated/Verified Findings Comparison

Note: For GitLeaks and detect-secrets, validated/verified counts are not available.

| Repository | Kingfisher Validated | TruffleHog Verified | GitLeaks Verified | detect-secrets Verified |
|------------|----------------------|---------------------|-------------------|-------------------------|
| croc | 0 | 0 | 0 | 0 |
| rails | 0 | 0 | 0 | 0 |
| ruby | 0 | 0 | 0 | 0 |
| gitlab | 6 | 6 | 0 | 0 |
| django | 0 | 0 | 0 | 0 |
| lucene | 0 | 0 | 0 | 0 |
| mongodb | 0 | 0 | 0 | 0 |
| linux | 0 | 0 | 0 | 0 |
| typescript | 0 | 0 | 0 | 0 |

### Network Requests Comparison
*'Network Requests' shows the total number of HTTP calls made during a scan. Since Gitleaks and detect‑secrets don’t validate secrets, they never make any network requests.*

| Repository | Kingfisher Network Requests | TruffleHog Network Requests | GitLeaks Network Requests | detect-secrets Network Requests |
|------------|-----------------------------|-----------------------------|---------------------------|----------------------------------|
| croc | 0 | 17 | 0 | 0 |
| rails | 1 | 25 | 0 | 0 |
| ruby | 3 | 33 | 0 | 0 |
| gitlab | 17 | 15624 | 0 | 0 |
| django | 0 | 66 | 0 | 0 |
| lucene | 0 | 116 | 0 | 0 |
| mongodb | 1 | 191 | 0 | 0 |
| linux | 0 | 287 | 0 | 0 |
| typescript | 0 | 10 | 0 | 0 |
### QuickChart.io Visualizations

#### Runtime Chart
*Lower runtimes are better*

![Runtime Comparison](https://quickchart.io/chart?c=%7B%22type%22%3A%22bar%22%2C%22data%22%3A%7B%22labels%22%3A%5B%22croc%22%2C%22rails%22%2C%22ruby%22%2C%22gitlab%22%2C%22django%22%2C%22lucene%22%2C%22mongodb%22%2C%22linux%22%2C%22typescript%22%5D%2C%22datasets%22%3A%5B%7B%22label%22%3A%22Kingfisher%22%2C%22data%22%3A%5B3.087692041%2C9.816560542%2C22.222204459%2C129.921919875%2C6.748027708%2C18.650581459%2C27.47587625%2C204.192040875%2C62.877494792%5D%7D%2C%7B%22label%22%3A%22TruffleHog%22%2C%22data%22%3A%5B17.667027792%2C24.4969155%2C133.286264708%2C335.819256375%2C248.135664708%2C91.367231833%2C180.311266375%2C585.00584475%2C182.478392708%5D%7D%2C%7B%22label%22%3A%22GitLeaks%22%2C%22data%22%3A%5B2.845539417%2C19.704876208%2C46.658975%2C285.6701695%2C22.446593958%2C53.793195375%2C174.406220375%2C517.420016958%2C164.260176625%5D%7D%2C%7B%22label%22%3A%22detect-secrets%22%2C%22data%22%3A%5B0.703465916%2C0.783118209%2C1.231432834%2C8.751082041%2C1.120182458%2C1.019824708%2C4.737797875%2C8.402164%2C7.170617042%5D%7D%5D%7D%2C%22options%22%3A%7B%22scales%22%3A%7B%22yAxes%22%3A%5B%7B%22ticks%22%3A%7B%22beginAtZero%22%3Atrue%7D%7D%5D%7D%2C%22title%22%3A%7B%22display%22%3A%22true%22%2C%22text%22%3A%22Runtime+Comparison+%28seconds%29%22%7D%7D%7D)


#### Validated/Verified Findings Chart
*Validated/Verified counts are reported where available*

![Findings Comparison](https://quickchart.io/chart?c=%7B%22type%22%3A%22bar%22%2C%22data%22%3A%7B%22labels%22%3A%5B%22croc%22%2C%22rails%22%2C%22ruby%22%2C%22gitlab%22%2C%22django%22%2C%22lucene%22%2C%22mongodb%22%2C%22linux%22%2C%22typescript%22%5D%2C%22datasets%22%3A%5B%7B%22label%22%3A%22detect-secrets%22%2C%22data%22%3A%5B0%2C0%2C0%2C0%2C0%2C0%2C0%2C0%2C0%5D%7D%2C%7B%22label%22%3A%22Kingfisher%22%2C%22data%22%3A%5B0%2C0%2C0%2C6%2C0%2C0%2C0%2C0%2C0%5D%7D%2C%7B%22label%22%3A%22TruffleHog%22%2C%22data%22%3A%5B0%2C0%2C0%2C6%2C0%2C0%2C0%2C0%2C0%5D%7D%2C%7B%22label%22%3A%22GitLeaks%22%2C%22data%22%3A%5B0%2C0%2C0%2C0%2C0%2C0%2C0%2C0%2C0%5D%7D%5D%7D%2C%22options%22%3A%7B%22scales%22%3A%7B%22yAxes%22%3A%5B%7B%22ticks%22%3A%7B%22beginAtZero%22%3Atrue%7D%7D%5D%7D%2C%22title%22%3A%7B%22display%22%3A%22true%22%2C%22text%22%3A%22Validated%2FVerified+Findings%22%7D%7D%7D)


*Lower runtimes are better. Validated/Verified counts are reported where available. 'Network Requests' indicates the number of HTTP requests made during scanning.*

OS: darwin  
Architecture: arm64  
CPU Cores: 16  
RAM: 48.00 GB  

