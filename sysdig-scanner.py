import os
import json
import subprocess
import requests
from typing import Dict, List, Optional

class SysdigScanner:
    def __init__(self, api_token: str, backend_url: str = "https://secure.sysdig.com"):
        """
        Initialize Sysdig scanner with API token and backend URL.
        
        Args:
            api_token (str): Sysdig API token
            backend_url (str): Sysdig backend URL (default: https://secure.sysdig.com)
        """
        self.api_token = api_token
        self.backend_url = backend_url
        self.headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json"
        }

    def scan_image(self, image_name: str, registry_credentials: Optional[Dict] = None) -> Dict:
        """
        Scan a container image using Sysdig scanner.
        
        Args:
            image_name (str): Name of the container image to scan
            registry_credentials (Dict, optional): Registry credentials if needed
            
        Returns:
            Dict: Scan results including vulnerabilities and compliance issues
        """
        try:
            # Prepare scan request
            scan_url = f"{self.backend_url}/api/scanning/v1/scan"
            payload = {
                "image": image_name,
                "force": True,
                "pull_credentials": registry_credentials
            }

            # Initiate scan
            response = requests.post(
                scan_url,
                headers=self.headers,
                json=payload
            )
            response.raise_for_status()
            scan_result = response.json()

            # Wait for scan to complete
            scan_id = scan_result["id"]
            while True:
                status = self._check_scan_status(scan_id)
                if status["status"] in ["completed", "failed"]:
                    break

            # Get detailed results
            return self._get_scan_results(scan_id)

        except Exception as e:
            return {"error": str(e)}

    def _check_scan_status(self, scan_id: str) -> Dict:
        """Check the status of a scan."""
        status_url = f"{self.backend_url}/api/scanning/v1/scan/{scan_id}"
        response = requests.get(status_url, headers=self.headers)
        return response.json()

    def _get_scan_results(self, scan_id: str) -> Dict:
        """Get detailed results of a completed scan."""
        results_url = f"{self.backend_url}/api/scanning/v1/scan/{scan_id}/result"
        response = requests.get(results_url, headers=self.headers)
        return response.json()

    def generate_report(self, scan_results: Dict, output_file: str = "scan_report.json") -> None:
        """
        Generate a report from scan results.
        
        Args:
            scan_results (Dict): Results from the scan
            output_file (str): Output file name
        """
        # Extract relevant information
        report = {
            "summary": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "total_vulnerabilities": 0
            },
            "vulnerabilities": [],
            "compliance_issues": [],
            "scan_time": scan_results.get("analysis_status", {}).get("analysis_time", "")
        }

        # Process vulnerabilities
        if "vulnerabilities" in scan_results:
            for vuln in scan_results["vulnerabilities"]:
                report["vulnerabilities"].append({
                    "id": vuln.get("id"),
                    "severity": vuln.get("severity"),
                    "package": vuln.get("package", {}).get("name"),
                    "version": vuln.get("package", {}).get("version"),
                    "fix_version": vuln.get("fix_version"),
                    "description": vuln.get("description")
                })
                report["summary"][vuln.get("severity", "low")] += 1
                report["summary"]["total_vulnerabilities"] += 1

        # Save report
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)

def main():
    # Example usage
    api_token = os.getenv("SYSDIG_API_TOKEN")
    if not api_token:
        raise ValueError("SYSDIG_API_TOKEN environment variable is required")

    scanner = SysdigScanner(api_token)
    
    # Example image scan
    image_name = "nginx:latest"
    scan_results = scanner.scan_image(image_name)
    
    if "error" not in scan_results:
        scanner.generate_report(scan_results)
        print(f"Scan completed and report generated for {image_name}")
    else:
        print(f"Scan failed: {scan_results['error']}")

if __name__ == "__main__":
    main()
