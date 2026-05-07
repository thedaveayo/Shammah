"""
Infrastructure Detection Service
Scans project files to detect languages, frameworks, and infrastructure
"""
import os
import json
import re
from typing import Dict, List, Optional
from pathlib import Path

class InfrastructureDetector:
    """Detects project infrastructure from files"""

    def detect(self, project_path: str) -> Dict:
        """
        Scan project directory and detect infrastructure
        Returns: {languages, frameworks, infrastructure, confidence}
        """
        result = {
            "languages": [],
            "frameworks": [],
            "infrastructure": [],
            "contexts": [],  # frontend, backend, mobile, etc.
            "confidence": 0.0
        }

        if not os.path.exists(project_path):
            return result

        # Scan for configuration files
        detectors = [
            self._detect_package_json,
            self._detect_requirements,
            self._detect_cargo_toml,
            self._detect_go_mod,
            self._detect_pom_xml,
            self._detect_gradle,
            self._detect_gemfile,
            self._detect_php_composer,
            self._detect_docker,
            self._detect_kubernetes,
            self._detect_terraform,
            self._detect_config_files,
        ]

        for detector in detectors:
            detector(project_path, result)

        # Determine contexts based on detected technologies
        self._determine_contexts(result)

        # Calculate confidence based on how many signals found
        signals = (
            len(result["languages"]) +
            len(result["frameworks"]) +
            len(result["infrastructure"])
        )
        result["confidence"] = min(1.0, signals / 10.0)

        return result

    def _determine_contexts(self, result: Dict):
        """Determine contexts (frontend, backend, mobile, etc.) based on detected technologies"""
        frameworks = set(result["frameworks"])
        languages = set(result["languages"])

        # Frontend frameworks
        frontend_frameworks = {
            "react", "angular", "vue", "svelte", "nextjs", "nuxtjs", 
            "gatsby", "remix", "astro", "blazor", "jquery"
        }
        if frameworks.intersection(frontend_frameworks):
            if "frontend" not in result["contexts"]:
                result["contexts"].append("frontend")

        # Backend frameworks
        backend_frameworks = {
            "express", "nestjs", "fastapi", "django", "flask", "rails", 
            "laravel", "spring", "aspnetcore", "gin", "fiber", "rocket",
            "actix-web", "axum"
        }
        if frameworks.intersection(backend_frameworks):
            if "backend" not in result["contexts"]:
                result["contexts"].append("backend")

        # Mobile frameworks
        mobile_technologies = {
            "flutter", "react-native", "ionic", "xamarin", "kotlin", 
            "swift", "native-ios", "native-android"
        }
        if frameworks.intersection(mobile_technologies) or languages.intersection({"kotlin", "swift"}):
            if "mobile" not in result["contexts"]:
                result["contexts"].append("mobile")

        # Cloud/DevOps
        if "docker" in result["infrastructure"] or "kubernetes" in result["infrastructure"]:
            if "cloud" not in result["contexts"]:
                result["contexts"].append("cloud")
    
    def _detect_package_json(self, project_path: str, result: Dict):
        """Detect Node.js project from package.json"""
        package_json = os.path.join(project_path, "package.json")

        if os.path.exists(package_json):
            try:
                with open(package_json, 'r') as f:
                    data = json.load(f)

                # Detect JavaScript/TypeScript
                result["languages"].append("javascript")

                # Detect TypeScript
                if os.path.exists(os.path.join(project_path, "tsconfig.json")):
                    if "typescript" not in result["languages"]:
                        result["languages"].append("typescript")

                # Detect frameworks from dependencies
                deps = data.get("dependencies", {})
                dev_deps = data.get("devDependencies", {})
                all_deps = {**deps, **dev_deps}

                # Frontend frameworks
                if "react" in all_deps:
                    result["frameworks"].append("react")
                if "angular" in all_deps:
                    result["frameworks"].append("angular")
                if "vue" in all_deps:
                    result["frameworks"].append("vue")
                if "svelte" in all_deps:
                    result["frameworks"].append("svelte")
                if "next" in all_deps:
                    result["frameworks"].append("nextjs")
                if "nuxt" in all_deps:
                    result["frameworks"].append("nuxtjs")
                if "gatsby" in all_deps:
                    result["frameworks"].append("gatsby")
                if "remix" in all_deps:
                    result["frameworks"].append("remix")
                if "astro" in all_deps:
                    result["frameworks"].append("astro")
                
                # Backend frameworks
                if "express" in all_deps:
                    result["frameworks"].append("express")
                if "nestjs" in all_deps:
                    result["frameworks"].append("nestjs")
                if "fastify" in all_deps:
                    result["frameworks"].append("fastify")
                if "koa" in all_deps:
                    result["frameworks"].append("koa")
                
                # Mobile frameworks
                if "react-native" in all_deps:
                    result["frameworks"].append("react-native")
                if "@ionic/react" in all_deps or "@ionic/vue" in all_deps:
                    result["frameworks"].append("ionic")
                
                # Build tools
                if "webpack" in all_deps or "vite" in all_deps or "rollup" in all_deps:
                    result["infrastructure"].append("build-tool")

            except (json.JSONDecodeError, IOError):
                pass

    def _detect_pom_xml(self, project_path: str, result: Dict):
        """Detect Java project from pom.xml"""
        pom_xml = os.path.join(project_path, "pom.xml")

        if os.path.exists(pom_xml):
            result["languages"].append("java")

            try:
                with open(pom_xml, 'r', encoding='utf-8') as f:
                    content = f.read().lower()

                # Detect frameworks from dependencies
                if "spring-boot-starter" in content:
                    result["frameworks"].append("spring-boot")
                    if "backend" not in result["contexts"]:
                        result["contexts"].append("backend")
                if "spring-web" in content:
                    result["frameworks"].append("spring")
                if "hibernate-core" in content:
                    result["frameworks"].append("hibernate")
                if "junit" in content:
                    result["infrastructure"].append("testing-framework")

            except IOError:
                pass

    def _detect_gradle(self, project_path: str, result: Dict):
        """Detect Gradle project from build.gradle"""
        build_gradle = os.path.join(project_path, "build.gradle")
        gradle_kts = os.path.join(project_path, "build.gradle.kts")

        if os.path.exists(build_gradle) or os.path.exists(gradle_kts):
            gradle_file = build_gradle if os.path.exists(build_gradle) else gradle_kts
            result["languages"].append("kotlin" if gradle_file.endswith(".kts") else "groovy")

            try:
                with open(gradle_file, 'r', encoding='utf-8') as f:
                    content = f.read().lower()

                if "org.jetbrains.kotlin" in content:
                    if "kotlin" not in result["languages"]:
                        result["languages"].append("kotlin")
                
                # Detect frameworks
                if "spring-boot" in content:
                    result["frameworks"].append("spring-boot")
                if "android" in content:
                    result["frameworks"].append("android")
                    if "mobile" not in result["contexts"]:
                        result["contexts"].append("mobile")

            except IOError:
                pass

    def _detect_gemfile(self, project_path: str, result: Dict):
        """Detect Ruby project from Gemfile"""
        gemfile = os.path.join(project_path, "Gemfile")

        if os.path.exists(gemfile):
            result["languages"].append("ruby")

            try:
                with open(gemfile, 'r') as f:
                    content = f.read().lower()

                if "rails" in content:
                    result["frameworks"].append("rails")
                    if "backend" not in result["contexts"]:
                        result["contexts"].append("backend")
                if "rspec" in content:
                    result["infrastructure"].append("testing-framework")

            except IOError:
                pass

    def _detect_php_composer(self, project_path: str, result: Dict):
        """Detect PHP project from composer.json"""
        composer_json = os.path.join(project_path, "composer.json")

        if os.path.exists(composer_json):
            result["languages"].append("php")

            try:
                with open(composer_json, 'r') as f:
                    data = json.load(f)

                deps = data.get("require", {})
                
                if "laravel/framework" in deps:
                    result["frameworks"].append("laravel")
                    if "backend" not in result["contexts"]:
                        result["contexts"].append("backend")
                if "symfony/framework-bundle" in deps:
                    result["frameworks"].append("symfony")
                    if "backend" not in result["contexts"]:
                        result["contexts"].append("backend")
                if "yiisoft/yii2" in deps:
                    result["frameworks"].append("yii2")

            except (json.JSONDecodeError, IOError):
                pass

    def _detect_kubernetes(self, project_path: str, result: Dict):
        """Detect Kubernetes usage from YAML files"""
        for root, dirs, files in os.walk(project_path):
            for file in files:
                if file.endswith(".yaml") or file.endswith(".yml"):
                    yaml_path = os.path.join(root, file)
                    try:
                        with open(yaml_path, 'r') as f:
                            content = f.read().lower()

                        if "apiVersion" in content and "kind:" in content:
                            if "Deployment" in content or "Service" in content or "Pod" in content:
                                result["infrastructure"].append("kubernetes")
                                if "cloud" not in result["contexts"]:
                                    result["contexts"].append("cloud")
                                break

                    except IOError:
                        pass

    def _detect_config_files(self, project_path: str, result: Dict):
        """Detect infrastructure from common configuration files"""
        config_files = {
            "Procfile": ["heroku"],
            "requirements.txt": ["python"],
            "setup.py": ["python"],
            "pyproject.toml": ["python"],
            "go.mod": ["go"],
            "Cargo.toml": ["rust"],
            "Gemfile": ["ruby"],
            "composer.json": ["php"],
            "Podfile": ["ios", "mobile"],
            "build.sbt": ["scala"],
            "mix.exs": ["elixir"]
        }

        for filename, tech_list in config_files.items():
            filepath = os.path.join(project_path, filename)
            if os.path.exists(filepath):
                for tech in tech_list:
                    if tech in ["python", "go", "rust", "ruby", "php", "scala", "elixir"]:
                        if tech not in result["languages"]:
                            result["languages"].append(tech)
                    else:
                        if tech not in result["infrastructure"]:
                            result["infrastructure"].append(tech)
    
    def _detect_requirements(self, project_path: str, result: Dict):
        """Detect Python project from requirements.txt"""
        requirements = os.path.join(project_path, "requirements.txt")
        
        if os.path.exists(requirements):
            result["languages"].append("python")
            
            try:
                with open(requirements, 'r') as f:
                    content = f.read().lower()
                
                if "django" in content:
                    result["frameworks"].append("django")
                if "flask" in content:
                    result["frameworks"].append("flask")
                if "fastapi" in content:
                    result["frameworks"].append("fastapi")
                    
            except IOError:
                pass
        
        # Also check for pyproject.toml
        if os.path.exists(os.path.join(project_path, "pyproject.toml")):
            if "python" not in result["languages"]:
                result["languages"].append("python")
    
    def _detect_cargo_toml(self, project_path: str, result: Dict):
        """Detect Rust project from Cargo.toml"""
        cargo_toml = os.path.join(project_path, "Cargo.toml")
        
        if os.path.exists(cargo_toml):
            result["languages"].append("rust")
    
    def _detect_go_mod(self, project_path: str, result: Dict):
        """Detect Go project from go.mod"""
        go_mod = os.path.join(project_path, "go.mod")
        
        if os.path.exists(go_mod):
            result["languages"].append("go")
    
    def _detect_docker(self, project_path: str, result: Dict):
        """Detect Docker usage"""
        docker_compose = os.path.join(project_path, "docker-compose.yml")
        dockerfile = os.path.join(project_path, "Dockerfile")
        
        if os.path.exists(docker_compose) or os.path.exists(dockerfile):
            result["infrastructure"].append("docker")
    
    def _detect_terraform(self, project_path: str, result: Dict):
        """Detect Terraform infrastructure"""
        # Look for .tf files
        for root, dirs, files in os.walk(project_path):
            for file in files:
                if file.endswith(".tf"):
                    result["infrastructure"].append("terraform")
                    
                    # Try to detect cloud provider
                    tf_path = os.path.join(root, file)
                    try:
                        with open(tf_path, 'r') as f:
                            content = f.read().lower()
                        
                        if "aws_" in content:
                            result["infrastructure"].append("aws")
                        if "google_" in content or "gcp" in content:
                            result["infrastructure"].append("gcp")
                        if "azurerm" in content or "azure_" in content:
                            result["infrastructure"].append("azure")
                            
                    except IOError:
                        pass
                    break
